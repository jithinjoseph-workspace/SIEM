//! JSON helpers and the scanner's error type.

use serde_json::Value;
use std::fmt;

/// Compact JSON with object keys in sorted (byte) order, whatever map type serde_json uses.
pub fn compact(v: &Value) -> String {
    let mut s = String::new();
    write_compact(v, &mut s);
    s
}

fn write_compact(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_compact(&m[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Text member, or "" when missing or not a text.
pub fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Text member that must be a text when present (json error 302 otherwise).
/// Text member, empty when missing, `null` or not a text: agent details the agent database has
/// not filled in yet (a new agent, an agent without an address) must not stop its scan.
pub fn text_or_empty(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

pub fn opt_text(v: &Value, key: &str) -> Res<String> {
    match v.get(key) {
        None => Ok(String::new()),
        Some(Value::String(x)) => Ok(x.clone()),
        Some(o) => Err(wrong_type("string", o)),
    }
}

/// Text member that must exist and be a text.
pub fn req_text(v: &Value, key: &str) -> Res<String> {
    match v.get(key) {
        None => Err(key_missing(key)),
        Some(Value::String(x)) => Ok(x.clone()),
        Some(o) => Err(wrong_type("string", o)),
    }
}

/// The scanner's errors. `Json` keeps the parser error id for the event log lines.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Json { id: u16, text: String },
    /// The agent database has no data for this agent yet; the event waits and retries.
    NotReady { agent: String, text: String },
    /// Some agents of a re-scan could not be read yet.
    Incomplete { agents: Vec<String>, no_index: bool },
    Other(String),
}

pub type Res<T> = Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json { text, .. } | Error::NotReady { text, .. } | Error::Other(text) => {
                f.write_str(text)
            }
            Error::Incomplete { .. } => f.write_str("Error executing rescan for multiple agents."),
        }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

pub fn key_missing(k: &str) -> Error {
    Error::Json { id: 403, text: key_missing_text(k) }
}
pub fn key_missing_text(k: &str) -> String {
    format!("JSON key '{k}' not found")
}
pub fn wrong_type(expected: &str, v: &Value) -> Error {
    Error::Json { id: 302, text: wrong_type_text(expected, v) }
}
pub fn wrong_type_text(expected: &str, v: &Value) -> String {
    format!("JSON value must be {expected}, but is {}", type_name(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_sorts_keys() {
        assert_eq!(compact(&json!({"b":1,"a":{"d":[1,"x"],"c":null}})), r#"{"a":{"c":null,"d":[1,"x"]},"b":1}"#);
        assert_eq!(compact(&json!({"x":10.0})), r#"{"x":10.0}"#);
    }
}
