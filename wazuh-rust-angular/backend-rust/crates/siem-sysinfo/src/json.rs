//! Building nlohmann values the way the C++ assigns them.

use std::collections::BTreeMap;

pub use siem_njson::Value;

/// `primaryArraySeparator` / `secondaryArraySeparator` (sysInfo.hpp)
pub const PRIMARY_ARRAY_SEPARATOR: &str = ",";
pub const SECONDARY_ARRAY_SEPARATOR: &str = ":";

/// A JSON string from bytes.
pub fn s(v: impl AsRef<[u8]>) -> Value {
    Value::Str(v.as_ref().to_vec())
}

/// An unsigned number (`DWORD`, `ULONGLONG`, `size_t` assignments).
pub fn u(v: u64) -> Value {
    Value::UInt(v)
}

/// A signed number (`int`, `LONG`, `int64_t` assignments).
pub fn i(v: i64) -> Value {
    Value::Int(v)
}

/// A float (`double` assignments).
pub fn f(v: f64) -> Value {
    Value::Float(v)
}

/// `json[key] = value` on an object being built.
#[derive(Default)]
pub struct Obj(pub BTreeMap<Vec<u8>, Value>);

impl Obj {
    pub fn new() -> Self {
        Obj(BTreeMap::new())
    }
    pub fn set(&mut self, k: &str, v: Value) -> &mut Self {
        self.0.insert(k.as_bytes().to_vec(), v);
        self
    }
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.0.get(k.as_bytes())
    }
    pub fn contains(&self, k: &str) -> bool {
        self.0.contains_key(k.as_bytes())
    }
    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// The string of a value (`get<std::string>()` on a string), else "".
pub fn as_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::Str(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

/// `j.contains(k) && !j[k].get<std::string>().empty() ? j[k] : UNKNOWN_VALUE`
pub fn non_empty_or_unknown(o: &Obj, k: &str) -> Value {
    match o.get(k) {
        Some(Value::Str(b)) if !b.is_empty() => Value::Str(b.clone()),
        _ => s(crate::UNKNOWN_VALUE),
    }
}

/// `j.value(k, default)`: the value when the key is there (any type).
pub fn value_or(o: &Obj, k: &str, default: Value) -> Value {
    o.get(k).cloned().unwrap_or(default)
}
