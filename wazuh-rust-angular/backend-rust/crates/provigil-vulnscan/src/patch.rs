//! JSON patch (add, remove, replace, move, copy, test) with JSON pointers.

use crate::json::{compact, key_missing_text};
use serde_json::{Map, Value};

type R<T> = Result<T, String>;

fn out_of_range(i: impl std::fmt::Display) -> String {
    format!("JSON array index {i} is out of range")
}

/// Splits a pointer into its unescaped tokens.
fn tokens(path: &str) -> R<Vec<String>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if !path.starts_with('/') {
        return Err(format!("JSON pointer must be empty or begin with '/' - was: '{path}'"));
    }
    path[1..]
        .split('/')
        .map(|t| {
            let b = t.as_bytes();
            for (i, c) in b.iter().enumerate() {
                if *c == b'~' && !matches!(b.get(i + 1), Some(b'0') | Some(b'1')) {
                    return Err("JSON pointer escape character '~' must be followed with '0' or '1'".to_string());
                }
            }
            Ok(t.replace("~1", "/").replace("~0", "~"))
        })
        .collect()
}

fn array_index(t: &str) -> R<usize> {
    if t.len() > 1 && t.starts_with('0') {
        return Err(format!("JSON array index '{t}' must not begin with '0'"));
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("JSON array index '{t}' is not a number"));
    }
    t.parse::<usize>().map_err(|_| format!("JSON array index {t} is too large"))
}

fn get<'a>(doc: &'a Value, toks: &[String]) -> R<&'a Value> {
    let mut cur = doc;
    for t in toks {
        cur = match cur {
            Value::Object(m) => m.get(t).ok_or_else(|| key_missing_text(t))?,
            Value::Array(a) => {
                if t == "-" {
                    return Err(format!("JSON array index '-' ({}) is out of range", a.len()));
                }
                let i = array_index(t)?;
                a.get(i).ok_or_else(|| out_of_range(i))?
            }
            _ => return Err(format!("JSON pointer token '{t}' cannot be resolved")),
        };
    }
    Ok(cur)
}

fn get_mut<'a>(doc: &'a mut Value, toks: &[String]) -> R<&'a mut Value> {
    let mut cur = doc;
    for t in toks {
        cur = match cur {
            Value::Object(m) => m.get_mut(t).ok_or_else(|| key_missing_text(t))?,
            Value::Array(a) => {
                if t == "-" {
                    return Err(format!("JSON array index '-' ({}) is out of range", a.len()));
                }
                let i = array_index(t)?;
                let n = a.len();
                a.get_mut(i).ok_or_else(|| out_of_range(i.max(n)))?
            }
            _ => return Err(format!("JSON pointer token '{t}' cannot be resolved")),
        };
    }
    Ok(cur)
}

/// Adds at `toks`: the parent must exist (normal walking rules); a scalar parent is left as is.
fn add(doc: &mut Value, toks: &[String], val: Value) -> R<()> {
    let Some((last, parent)) = toks.split_last() else {
        *doc = val;
        return Ok(());
    };
    let p = get_mut(doc, parent)?;
    match p {
        Value::Null => {
            let mut m = Map::new();
            m.insert(last.clone(), val);
            *p = Value::Object(m);
        }
        Value::Object(m) => {
            m.insert(last.clone(), val);
        }
        Value::Array(a) => {
            if last == "-" {
                a.push(val);
            } else {
                let i = array_index(last)?;
                if i > a.len() {
                    return Err(out_of_range(i));
                }
                a.insert(i, val);
            }
        }
        _ => {}
    }
    Ok(())
}

fn remove(doc: &mut Value, toks: &[String]) -> R<()> {
    let Some((last, parent)) = toks.split_last() else {
        return Err("JSON pointer has no parent".into());
    };
    match get_mut(doc, parent)? {
        Value::Object(m) => {
            m.remove(last).ok_or_else(|| key_missing_text(last))?;
        }
        Value::Array(a) => {
            let i = array_index(last)?;
            if i >= a.len() {
                return Err(out_of_range(i));
            }
            a.remove(i);
        }
        // A parent that is not an object or array (null included) is left as is.
        _ => {}
    }
    Ok(())
}

/// Applies `patch` to `doc`.
pub fn apply(doc: &mut Value, patch: &Value) -> R<()> {
    let ops = patch.as_array().filter(|a| a.iter().all(Value::is_object)).ok_or("JSON patch must be an array of objects")?;
    for op in ops {
        let name = match op.get("op") {
            None => return Err("JSON patch operation must have member 'op'".into()),
            Some(Value::String(s)) => s.as_str(),
            Some(_) => return Err("JSON patch operation must have text member 'op'".into()),
        };
        let text_member = |m: &str| -> R<String> {
            match op.get(m) {
                None => Err(format!("JSON patch operation '{name}' must have member '{m}'")),
                Some(Value::String(s)) => Ok(s.clone()),
                Some(_) => Err(format!("JSON patch operation '{name}' must have text member '{m}'")),
            }
        };
        let value = || op.get("value").cloned().ok_or_else(|| format!("JSON patch operation '{name}' must have member 'value'"));
        match name {
            "add" | "remove" | "replace" | "move" | "copy" | "test" => {}
            _ => return Err(format!("JSON patch operation value '{name}' is invalid")),
        }
        let path = tokens(&text_member("path")?)?;
        match name {
            "add" => add(doc, &path, value()?)?,
            "remove" => remove(doc, &path)?,
            "replace" => {
                let v = value()?;
                *get_mut(doc, &path)? = v;
            }
            "move" => {
                let from = tokens(&text_member("from")?)?;
                let v = get(doc, &from)?.clone();
                remove(doc, &from)?;
                add(doc, &path, v)?;
            }
            "copy" => {
                let from = tokens(&text_member("from")?)?;
                let v = get(doc, &from)?.clone();
                add(doc, &path, v)?;
            }
            _ => {
                let v = value()?;
                if get(doc, &path).ok() != Some(&v) {
                    return Err(format!("JSON patch test failed: {}", compact(op)));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(doc: Value, p: Value) -> R<Value> {
        let mut d = doc;
        apply(&mut d, &p).map(|_| d)
    }

    #[test]
    fn operations() {
        let d = json!({"a":[1,2],"b":{"c":"x"}});
        let p = json!([
            {"op":"add","path":"/a/1","value":9},
            {"op":"add","path":"/a/-","value":3},
            {"op":"remove","path":"/a/0"},
            {"op":"replace","path":"/b/c","value":"y"},
            {"op":"copy","from":"/b","path":"/e"},
            {"op":"move","from":"/b/c","path":"/d"},
            {"op":"test","path":"/d","value":"y"}
        ]);
        assert_eq!(run(d.clone(), p).unwrap(), json!({"a":[9,2,3],"b":{},"d":"y","e":{"c":"y"}}));
        let e = |p: Value| run(d.clone(), p).unwrap_err();
        assert_eq!(e(json!([{"op":"replace","path":"/zz","value":1}])), "JSON key 'zz' not found");
        assert_eq!(e(json!([{"op":"add","path":"/a/9","value":1}])), "JSON array index 9 is out of range");
        assert_eq!(e(json!([{"op":"add","path":"/x/y","value":1}])), "JSON key 'x' not found");
        assert_eq!(e(json!([{"op":"replace","path":"/nothere/x","value":1}])), "JSON key 'nothere' not found");
        assert_eq!(e(json!([{"op":"test","path":"/b/c","value":"z"}])), r#"JSON patch test failed: {"op":"test","path":"/b/c","value":"z"}"#);
        assert_eq!(e(json!({"op":"add"})), "JSON patch must be an array of objects");
        assert_eq!(e(json!([{}])), "JSON patch operation must have member 'op'");
        assert_eq!(e(json!([{"op":"add","path":"/q"}])), "JSON patch operation 'add' must have member 'value'");
        assert_eq!(e(json!([{"op":"bad","path":""}])), "JSON patch operation value 'bad' is invalid");
        assert_eq!(e(json!([{"op":"remove","path":""}])), "JSON pointer has no parent");
        assert_eq!(e(json!([{"op":"remove","path":"a"}])), "JSON pointer must be empty or begin with '/' - was: 'a'");
        assert_eq!(e(json!([{"op":"remove","path":"/a/01"}])), "JSON array index '01' must not begin with '0'");
        assert_eq!(e(json!([{"op":"remove","path":"/~2"}])), "JSON pointer escape character '~' must be followed with '0' or '1'");
        assert_eq!(e(json!([{"op":"replace","path":"/a/-","value":1}])), "JSON array index '-' (2) is out of range");
        assert_eq!(e(json!([{"op":"replace","path":"/b/c/d","value":1}])), "JSON pointer token 'd' cannot be resolved");
        assert_eq!(run(d.clone(), json!([{"op":"replace","path":"","value":{"n":1}}])).unwrap(), json!({"n":1}));
        // D4: the parent must exist.
        assert_eq!(run(json!({"c":{}}), json!([{"op":"add","path":"/c/q/r","value":1}])).unwrap_err(), "JSON key 'q' not found");
        assert_eq!(run(json!({"a":[]}), json!([{"op":"add","path":"/a/3/x","value":1}])).unwrap_err(), "JSON array index 3 is out of range");
        assert_eq!(run(json!({"n":null}), json!([{"op":"add","path":"/n/k","value":1}])).unwrap(), json!({"n":{"k":1}}));
        // D5: scalar parents of add, non-container parents of remove: nothing changes, no error.
        assert_eq!(run(json!({"f":3}), json!([{"op":"add","path":"/f/g","value":1}])).unwrap(), json!({"f":3}));
        assert_eq!(run(json!({"n":null}), json!([{"op":"remove","path":"/n/k"}])).unwrap(), json!({"n":null}));
        assert_eq!(run(json!({"s":"t"}), json!([{"op":"remove","path":"/s/k"}])).unwrap(), json!({"s":"t"}));
    }
}
