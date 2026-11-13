//! The JSON documents of the agent-database protocol.
//!
//! Requests and answers on that protocol are byte-exact, so this type keeps what a general JSON
//! library would normalise away:
//!
//! * objects are member lists in document order, keys may repeat, and lookups ignore ASCII case;
//! * strings are bytes (never checked for UTF-8) and end at a zero byte, also one written `\u0000`;
//! * a number keeps its value and an `int` view clamped to the i32 range;
//! * numbers print as an integer when they are one, else with 15 significant digits when those
//!   read back to the same value, else 17;
//! * the compact printer adds no spaces; the indented printer uses tabs.
//!
//! See [`parse`] for the reading rules and the error offset.

mod parse;
mod print;

pub use parse::{parse, parse_with_opts, MAX_DEPTH};
pub use print::fmt_f6;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    False,
    True,
    Null,
    /// The value and its i32 view ([`clamp_i32`]).
    Number { double: f64, int: i32 },
    String(Vec<u8>),
    Array(Vec<Json>),
    /// Members in document order; keys may repeat.
    Object(Vec<(Vec<u8>, Json)>),
}

/// The i32 view of a number: clamped to the i32 range, NaN as `i32::MIN`.
pub fn clamp_i32(d: f64) -> i32 {
    if d.is_nan() {
        i32::MIN
    } else {
        // `as` truncates toward zero and clamps to the range
        d as i32
    }
}

impl Json {
    pub fn number(d: f64) -> Json {
        Json::Number { double: d, int: clamp_i32(d) }
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

    /// Appends a member to an object (a repeated key is kept twice); nothing on other values.
    pub fn add(&mut self, key: impl AsRef<[u8]>, v: Json) -> &mut Self {
        if let Json::Object(m) = self {
            m.push((key.as_ref().to_vec(), v));
        }
        self
    }

    /// Appends an element to an array; nothing on other values.
    pub fn push(&mut self, v: Json) -> &mut Self {
        if let Json::Array(a) = self {
            a.push(v);
        }
        self
    }

    fn position(&self, key: &[u8]) -> Option<usize> {
        match self {
            Json::Object(m) => m.iter().position(|(k, _)| k.eq_ignore_ascii_case(key)),
            _ => None,
        }
    }

    /// The first member whose key equals `key` ignoring ASCII case.
    pub fn get(&self, key: &str) -> Option<&Json> {
        let i = self.position(key.as_bytes())?;
        match self {
            Json::Object(m) => Some(&m[i].1),
            _ => None,
        }
    }

    /// [`get`](Self::get) with a key in bytes.
    pub fn get_bytes(&self, key: &[u8]) -> Option<&Json> {
        let i = self.position(key)?;
        match self {
            Json::Object(m) => Some(&m[i].1),
            _ => None,
        }
    }

    pub fn get_mut_bytes(&mut self, key: &[u8]) -> Option<&mut Json> {
        let i = self.position(key)?;
        match self {
            Json::Object(m) => Some(&mut m[i].1),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        let i = self.position(key.as_bytes())?;
        match self {
            Json::Object(m) => Some(&mut m[i].1),
            _ => None,
        }
    }

    /// Takes out the member [`get`](Self::get) finds.
    pub fn remove(&mut self, key: &str) -> Option<Json> {
        let i = self.position(key.as_bytes())?;
        match self {
            Json::Object(m) => Some(m.remove(i).1),
            _ => None,
        }
    }

    /// A string's text (invalid UTF-8 replaced).
    pub fn as_str(&self) -> Option<std::borrow::Cow<'_, str>> {
        self.as_bytes().map(String::from_utf8_lossy)
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number { double, .. } => Some(*double),
            _ => None,
        }
    }

    /// A number's i32 view; `true` counts as 1.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Json::Number { int, .. } => Some(*int),
            Json::True => Some(1),
            _ => None,
        }
    }

    /// The elements of an array or the values of an object.
    pub fn children(&self) -> Vec<&Json> {
        match self {
            Json::Array(a) => a.iter().collect(),
            Json::Object(m) => m.iter().map(|(_, v)| v).collect(),
            _ => Vec::new(),
        }
    }

    /// Elements or members; 0 for other values.
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

    /// Indented with tabs.
    pub fn print(&self) -> Vec<u8> {
        let mut out = Vec::new();
        print::value(self, &mut out, Some(0));
        out
    }

    /// Compact.
    pub fn print_unformatted(&self) -> Vec<u8> {
        let mut out = Vec::new();
        print::value(self, &mut out, None);
        out
    }
}
