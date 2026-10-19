//! The JSON behaviour of the Python integration scripts: `json.load`
//! (ordered objects, ints vs floats, NaN/Infinity), `json.dumps` with the
//! default separators and `ensure_ascii`, and `repr()` for the debug log.

/// A Python JSON value. Ints keep their digits (Python ints are unbounded).
#[derive(Debug, Clone, PartialEq)]
pub enum Py {
    None,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Py>),
    /// Insertion order; a repeated key keeps its first position, last value.
    Dict(Vec<(String, Py)>),
}

impl Py {
    pub fn get(&self, k: &str) -> Option<&Py> {
        match self {
            Py::Dict(m) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, k: &str) -> Option<&mut Py> {
        match self {
            Py::Dict(m) => m.iter_mut().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `d[k] = v`
    pub fn set(&mut self, k: &str, v: Py) {
        if let Py::Dict(m) = self {
            match m.iter_mut().find(|(x, _)| x == k) {
                Some((_, slot)) => *slot = v,
                None => m.push((k.to_string(), v)),
            }
        }
    }

    /// `d.pop(k)`
    pub fn remove(&mut self, k: &str) {
        if let Py::Dict(m) = self {
            m.retain(|(x, _)| x != k);
        }
    }

    /// `d.update(other)`
    pub fn update(&mut self, other: &Py) {
        if let Py::Dict(o) = other {
            for (k, v) in o {
                self.set(k, v.clone());
            }
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Py::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Py::None => false,
            Py::Bool(b) => *b,
            Py::Int(i) => i.trim_start_matches('-').trim_start_matches('0') != "",
            Py::Float(f) => *f != 0.0,
            Py::Str(s) => !s.is_empty(),
            Py::List(l) => !l.is_empty(),
            Py::Dict(d) => !d.is_empty(),
        }
    }

    /// The numeric value of an int or float (comparisons such as `level <= 4`).
    pub fn num(&self) -> Option<f64> {
        match self {
            Py::Int(i) => i.parse::<f64>().ok(),
            Py::Float(f) => Some(*f),
            Py::Bool(b) => Some(*b as i32 as f64),
            _ => None,
        }
    }

    pub fn dict() -> Py {
        Py::Dict(Vec::new())
    }

    pub fn int(i: i64) -> Py {
        Py::Int(i.to_string())
    }

    pub fn str(s: impl Into<String>) -> Py {
        Py::Str(s.into())
    }
}

/// Builds a dict from pairs.
pub fn dict(pairs: Vec<(&str, Py)>) -> Py {
    let mut d = Py::dict();
    for (k, v) in pairs {
        d.set(k, v);
    }
    d
}

// ------------------------------------------------------------- json.loads

pub struct ParseError(pub String);

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn err<T>(&self, m: &str) -> Result<T, ParseError> {
        Err(ParseError(format!("{m}: char {}", self.i)))
    }

    fn lit(&mut self, w: &str) -> bool {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Py, ParseError> {
        self.ws();
        let Some(&c) = self.s.get(self.i) else { return self.err("Expecting value") };
        match c {
            b'{' => {
                self.i += 1;
                let mut d = Py::dict();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(d);
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return self.err("Expecting property name enclosed in double quotes");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return self.err("Expecting ':' delimiter");
                    }
                    self.i += 1;
                    let v = self.value()?;
                    d.set(&k, v);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(d);
                        }
                        _ => return self.err("Expecting ',' delimiter"),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut l = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Py::List(l));
                }
                loop {
                    l.push(self.value()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Py::List(l));
                        }
                        _ => return self.err("Expecting ',' delimiter"),
                    }
                }
            }
            b'"' => Ok(Py::Str(self.string()?)),
            _ => {
                if self.lit("null") {
                    return Ok(Py::None);
                }
                if self.lit("true") {
                    return Ok(Py::Bool(true));
                }
                if self.lit("false") {
                    return Ok(Py::Bool(false));
                }
                if self.lit("NaN") {
                    return Ok(Py::Float(f64::NAN));
                }
                if self.lit("Infinity") {
                    return Ok(Py::Float(f64::INFINITY));
                }
                if self.lit("-Infinity") {
                    return Ok(Py::Float(f64::NEG_INFINITY));
                }
                self.number()
            }
        }
    }

    fn number(&mut self) -> Result<Py, ParseError> {
        let st = self.i;
        let b = self.s;
        let mut i = self.i;
        if b.get(i) == Some(&b'-') {
            i += 1;
        }
        match b.get(i) {
            Some(b'0') => i += 1,
            Some(c) if c.is_ascii_digit() => {
                while b.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
            }
            _ => return self.err("Expecting value"),
        }
        let mut float = false;
        if b.get(i) == Some(&b'.') && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            float = true;
            i += 1;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        if matches!(b.get(i), Some(b'e' | b'E')) {
            let mut j = i + 1;
            if matches!(b.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            if b.get(j).is_some_and(u8::is_ascii_digit) {
                float = true;
                i = j;
                while b.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
            }
        }
        self.i = i;
        let t = std::str::from_utf8(&b[st..i]).unwrap_or("0");
        if float {
            Ok(Py::Float(t.parse::<f64>().unwrap_or(f64::NAN)))
        } else {
            // int(t): "-0" is 0
            let neg = t.starts_with('-');
            let digits = t.trim_start_matches('-');
            Ok(Py::Int(if neg && digits != "0" { format!("-{digits}") } else { digits.to_string() }))
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out: Vec<u16> = Vec::new();
        loop {
            let Some(&c) = self.s.get(self.i) else { return self.err("Unterminated string starting at") };
            match c {
                b'"' => {
                    self.i += 1;
                    // lone surrogates cannot live in a Rust String
                    return Ok(String::from_utf16_lossy(&out));
                }
                b'\\' => {
                    let e = self.s.get(self.i + 1).copied();
                    self.i += 2;
                    match e {
                        Some(b'"') => out.push('"' as u16),
                        Some(b'\\') => out.push('\\' as u16),
                        Some(b'/') => out.push('/' as u16),
                        Some(b'b') => out.push(8),
                        Some(b'f') => out.push(12),
                        Some(b'n') => out.push(10),
                        Some(b'r') => out.push(13),
                        Some(b't') => out.push(9),
                        Some(b'u') => {
                            let h = self.s.get(self.i..self.i + 4).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u16::from_str_radix(h, 16).ok());
                            let Some(h) = h else { return self.err("Invalid \\uXXXX escape") };
                            out.push(h);
                            self.i += 4;
                        }
                        _ => return self.err("Invalid \\escape"),
                    }
                }
                c if c < 0x20 => return self.err("Invalid control character at"),
                _ => {
                    // one UTF-8 sequence
                    let len = match c {
                        0..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let seq = &self.s[self.i..(self.i + len).min(self.s.len())];
                    let t = String::from_utf8_lossy(seq);
                    out.extend(t.encode_utf16());
                    self.i += len;
                }
            }
        }
    }
}

/// `json.loads`
pub fn loads(text: &[u8]) -> Result<Py, ParseError> {
    let mut p = P { s: text, i: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != text.len() {
        return p.err("Extra data");
    }
    Ok(v)
}

// ------------------------------------------------------------- json.dumps

/// `float.__repr__`
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // shortest round-trip digits
    let e = format!("{:e}", f);
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.trim_start_matches('-').chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    let sign = if neg { "-" } else { "" };
    if -4 < decpt && decpt <= 16 {
        let n = digits.len() as i32;
        let s = if decpt <= 0 {
            format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
        } else if decpt >= n {
            format!("{}{}.0", digits, "0".repeat((decpt - n) as usize))
        } else {
            format!("{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
        };
        format!("{sign}{s}")
    } else {
        let m = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits };
        let x = decpt - 1;
        format!("{sign}{m}e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs())
    }
}

fn dump_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e && (c as u32) != 0x7f => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn dump(v: &Py, out: &mut String) {
    match v {
        Py::None => out.push_str("null"),
        Py::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Py::Int(i) => out.push_str(i),
        Py::Float(f) => out.push_str(&match float_repr(*f).as_str() {
            "nan" => "NaN".to_string(),
            "inf" => "Infinity".to_string(),
            "-inf" => "-Infinity".to_string(),
            r => r.to_string(),
        }),
        Py::Str(s) => dump_str(s, out),
        Py::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump(x, out);
            }
            out.push(']');
        }
        Py::Dict(d) => {
            out.push('{');
            for (i, (k, x)) in d.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump_str(k, out);
                out.push_str(": ");
                dump(x, out);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(v)`
pub fn dumps(v: &Py) -> String {
    let mut s = String::new();
    dump(v, &mut s);
    s
}

// ------------------------------------------------------------- repr()

fn printable(c: char) -> bool {
    let u = c as u32;
    if u < 0x20 || (0x7f..=0xa0).contains(&u) || u == 0xad {
        return false;
    }
    !matches!(u, 0x1680 | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064 | 0x3000 | 0xfeff | 0xd800..=0xdfff | 0xe000..=0xf8ff)
}

/// `repr(str)`
pub fn str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(q);
    out
}

/// `repr(value)` / `str(dict)` as Python prints them.
pub fn repr(v: &Py) -> String {
    match v {
        Py::None => "None".into(),
        Py::Bool(b) => if *b { "True" } else { "False" }.into(),
        Py::Int(i) => i.clone(),
        Py::Float(f) => float_repr(*f),
        Py::Str(s) => str_repr(s),
        Py::List(l) => format!("[{}]", l.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Py::Dict(d) => format!("{{{}}}", d.iter().map(|(k, x)| format!("{}: {}", str_repr(k), repr(x))).collect::<Vec<_>>().join(", ")),
    }
}

/// `str(value)` (strings print bare).
pub fn to_str(v: &Py) -> String {
    match v {
        Py::Str(s) => s.clone(),
        x => repr(x),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(s: &str) -> String {
        dumps(&loads(s.as_bytes()).ok().unwrap())
    }

    #[test]
    fn python_dumps() {
        assert_eq!(rt(r#"{"a":1,"b":[1.5,1e16,0.0001,1e-5,100.0,-0],"c":"é\u0001\"/","a":2}"#), r#"{"a": 2, "b": [1.5, 1e+16, 0.0001, 1e-05, 100.0, 0], "c": "\u00e9\u0001\"/"}"#);
        assert_eq!(rt(r#"["\ud83d\ude00", NaN, -Infinity, 123456789012345678901234567890]"#), r#"["\ud83d\ude00", NaN, -Infinity, 123456789012345678901234567890]"#);
        assert_eq!(float_repr(1e15), "1000000000000000.0");
        assert_eq!(float_repr(1.0 / 3.0), "0.3333333333333333");
        assert_eq!(float_repr(-2.5e-7), "-2.5e-07");
    }

    #[test]
    fn python_repr() {
        let v = loads(r#"{"a":"it's","b":[true,null,1.0],"c":"x\tyé"}"#.as_bytes()).ok().unwrap();
        assert_eq!(repr(&v), r#"{'a': "it's", 'b': [True, None, 1.0], 'c': 'x\tyé'}"#);
    }

    #[test]
    fn strict_strings() {
        assert!(loads(b"{\"a\":\"x\ny\"}").is_err());
        assert!(loads(b"{\"a\":1} x").is_err());
    }
}
