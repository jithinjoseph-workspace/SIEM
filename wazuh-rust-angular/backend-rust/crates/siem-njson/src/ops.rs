//! The rest of `basic_json`'s interface the C++ modules use: `operator[]`,
//! `push_back`, `clear`, `empty`, `find`, `items`, `get<T>` for arithmetic
//! types and strings, and `operator==`. Errors are `what()` strings, and
//! [`exception_id`] gives `ex.id`.

use std::collections::BTreeMap;

use crate::Value;

fn type_err(id: i32, msg: String) -> Vec<u8> {
    format!("[json.exception.type_error.{id}] {msg}").into_bytes()
}

/// `ex.id` of a `what()` string (`[json.exception.<kind>.<id>] ...`).
pub fn exception_id(what: &[u8]) -> i32 {
    let s = String::from_utf8_lossy(what);
    s.strip_prefix("[json.exception.")
        .and_then(|r| r.split_once(']'))
        .and_then(|(k, _)| k.rsplit('.').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

impl Default for Value {
    /// `json()`: null
    fn default() -> Self {
        Value::Null
    }
}

impl Value {
    /// `json(std::string)`
    pub fn string(s: impl AsRef<[u8]>) -> Value {
        Value::Str(s.as_ref().to_vec())
    }

    /// `json::object()`
    pub fn object() -> Value {
        Value::Object(BTreeMap::new())
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Value::Str(_))
    }

    /// `is_number()`
    pub fn is_number(&self) -> bool {
        matches!(self, Value::Int(_) | Value::UInt(_) | Value::Float(_))
    }

    /// `is_number_unsigned()`
    pub fn is_number_unsigned(&self) -> bool {
        matches!(self, Value::UInt(_))
    }

    /// `is_number_float()`
    pub fn is_number_float(&self) -> bool {
        matches!(self, Value::Float(_))
    }

    /// `empty()`
    pub fn empty(&self) -> bool {
        match self {
            Value::Null => true,
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            _ => false,
        }
    }

    /// `clear()`: the empty value of the same type.
    pub fn clear(&mut self) {
        match self {
            Value::Bool(b) => *b = false,
            Value::Int(i) => *i = 0,
            Value::UInt(u) => *u = 0,
            Value::Float(f) => *f = 0.0,
            Value::Str(s) => s.clear(),
            Value::Array(a) => a.clear(),
            Value::Object(o) => o.clear(),
            Value::Null => {}
        }
    }

    /// `find(key)`: `None` (end) for non objects too.
    pub fn find(&self, key: &[u8]) -> Option<&Value> {
        match self {
            Value::Object(o) => o.get(key),
            _ => None,
        }
    }

    /// `at(key)` with a byte key.
    pub fn at_b(&self, key: &[u8]) -> Result<&Value, Vec<u8>> {
        match self {
            Value::Object(o) => match o.get(key) {
                Some(v) => Ok(v),
                None => {
                    let mut m = b"[json.exception.out_of_range.403] key '".to_vec();
                    m.extend_from_slice(key);
                    m.extend_from_slice(b"' not found");
                    Err(m)
                }
            },
            v => Err(type_err(304, format!("cannot use at() with {}", v.type_name()))),
        }
    }

    /// Non-const `operator[](key)`: null becomes an object, a missing key
    /// is inserted as null.
    pub fn index_mut(&mut self, key: &[u8]) -> Result<&mut Value, Vec<u8>> {
        if self.is_null() {
            *self = Value::object();
        }
        match self {
            Value::Object(o) => Ok(o.entry(key.to_vec()).or_insert(Value::Null)),
            v => Err(type_err(305, format!("cannot use operator[] with a string argument with {}", v.type_name()))),
        }
    }

    /// `j[key] = v`
    pub fn set(&mut self, key: &[u8], v: Value) -> Result<(), Vec<u8>> {
        *self.index_mut(key)? = v;
        Ok(())
    }

    /// `push_back(v)`: null becomes an array.
    pub fn push_back(&mut self, v: Value) -> Result<(), Vec<u8>> {
        if self.is_null() {
            *self = Value::Array(Vec::new());
        }
        match self {
            Value::Array(a) => {
                a.push(v);
                Ok(())
            }
            o => Err(type_err(308, format!("cannot use push_back() with {}", o.type_name()))),
        }
    }

    /// `items()`: (key, value); array keys are the indexes, primitives
    /// have the empty key.
    pub fn items(&self) -> Vec<(Vec<u8>, &Value)> {
        match self {
            Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), v)).collect(),
            Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string().into_bytes(), v)).collect(),
            Value::Null => Vec::new(),
            v => vec![(Vec::new(), v)],
        }
    }

    fn not_number(&self) -> Vec<u8> {
        type_err(302, format!("type must be number, but is {}", self.type_name()))
    }

    /// `get<int64_t>()` (and the other signed types before narrowing):
    /// numbers and booleans, `static_cast` semantics.
    pub fn get_i64_arith(&self) -> Result<i64, Vec<u8>> {
        match self {
            Value::UInt(u) => Ok(*u as i64),
            Value::Int(i) => Ok(*i),
            Value::Float(f) => Ok(crate::f64_to_i64(*f)),
            Value::Bool(b) => Ok(*b as i64),
            v => Err(v.not_number()),
        }
    }

    /// `get<uint64_t>()` / `get<unsigned long>()`
    pub fn get_u64(&self) -> Result<u64, Vec<u8>> {
        match self {
            Value::UInt(u) => Ok(*u),
            Value::Int(i) => Ok(*i as u64),
            Value::Float(f) => Ok(f64_to_u64(*f)),
            Value::Bool(b) => Ok(*b as u64),
            v => Err(v.not_number()),
        }
    }

    /// `get<int32_t>()`
    pub fn get_i32(&self) -> Result<i32, Vec<u8>> {
        match self {
            Value::Float(f) => Ok(f64_to_i32(*f)),
            v => v.get_i64_arith().map(|i| i as i32),
        }
    }

    /// `get<unsigned int>()`
    pub fn get_u32(&self) -> Result<u32, Vec<u8>> {
        match self {
            Value::Float(f) => Ok(f64_to_u64(*f) as u32),
            v => v.get_u64().map(|u| u as u32),
        }
    }

    /// `get<double>()`
    pub fn get_f64(&self) -> Result<f64, Vec<u8>> {
        match self {
            Value::UInt(u) => Ok(*u as f64),
            Value::Int(i) => Ok(*i as f64),
            Value::Float(f) => Ok(*f),
            Value::Bool(b) => Ok(*b as i64 as f64),
            v => Err(v.not_number()),
        }
    }

    /// `get<std::string>()`
    pub fn get_string(&self) -> Result<Vec<u8>, Vec<u8>> {
        match self {
            Value::Str(s) => Ok(s.clone()),
            v => Err(type_err(302, format!("type must be string, but is {}", v.type_name()))),
        }
    }

    /// `get<bool>()`
    pub fn get_bool_strict(&self) -> Result<bool, Vec<u8>> {
        self.get_bool()
    }

    /// `operator==` (numbers compare across their types).
    pub fn json_eq(&self, o: &Value) -> bool {
        use Value::*;
        match (self, o) {
            (Array(a), Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.json_eq(y)),
            (Object(a), Object(b)) => a.len() == b.len() && a.iter().zip(b).all(|((ka, va), (kb, vb))| ka == kb && va.json_eq(vb)),
            (Null, Null) => true,
            (Str(a), Str(b)) => a == b,
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (UInt(a), UInt(b)) => a == b,
            (Float(a), Float(b)) => a == b,
            (Int(a), Float(b)) => *a as f64 == *b,
            (Float(a), Int(b)) => *a == *b as f64,
            (UInt(a), Float(b)) => *a as f64 == *b,
            (Float(a), UInt(b)) => *a == *b as f64,
            (UInt(a), Int(b)) => *a as i64 == *b,
            (Int(a), UInt(b)) => *a == *b as i64,
            _ => false,
        }
    }
}

/// `static_cast<uint64_t>(double)` as gcc emits it on x86-64.
pub fn f64_to_u64(d: f64) -> u64 {
    if d.is_nan() {
        return 0x8000_0000_0000_0000;
    }
    if d < 9.223372036854775808e18 {
        crate::f64_to_i64(d) as u64
    } else if d < 1.8446744073709551616e19 {
        (crate::f64_to_i64(d - 9.223372036854775808e18) as u64) ^ 0x8000_0000_0000_0000
    } else {
        0x8000_0000_0000_0000
    }
}

/// `static_cast<int32_t>(double)` (cvttsd2si 32-bit): INT32_MIN out of range.
pub fn f64_to_i32(d: f64) -> i32 {
    if d.is_nan() || d >= 2147483648.0 || d <= -2147483649.0 {
        i32::MIN
    } else {
        d as i32
    }
}
