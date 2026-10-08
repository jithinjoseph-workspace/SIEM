//! Custom Output Search & Replace Formatter (custom_output_search_replace.c)
//!
//! Evaluates alert output templates replacing variables like `$(rule.id)`, `$(agent.name)`,
//! `$(srcip)`, and arbitrary nested JSON paths like `$(data.win.eventdata.user)` into final syslog/webhook text.

use regex::Regex;
use std::sync::LazyLock;

static VAR_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\(([\w.\-_]+)\)").unwrap());

/// Replace `$(variable.path)` placeholders in a template with values extracted from an event JSON object.
pub fn format_custom_output(template: &str, event: &serde_json::Value) -> String {
    VAR_REGEX
        .replace_all(template, |caps: &regex::Captures| {
            let key = &caps[1];
            extract_json_path(event, key).unwrap_or_else(|| "".to_string())
        })
        .to_string()
}

/// Traverse a dot-separated path in a JSON object (e.g. "agent.name" or "rule.id").
pub fn extract_json_path(val: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = val;
    for part in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                if let Some(next) = map.get(part) {
                    current = next;
                } else {
                    return None;
                }
            }
            serde_json::Value::Array(arr) => {
                if let Ok(idx) = part.parse::<usize>() {
                    if let Some(next) = arr.get(idx) {
                        current = next;
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}
