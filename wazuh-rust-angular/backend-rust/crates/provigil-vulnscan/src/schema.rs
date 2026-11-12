//! Record schemas of the feed (CVE record format 5 and translations) and the normaliser that
//! turns feed JSON into the stored form.

use serde_json::{Map, Number, Value};

#[derive(Clone, Copy)]
pub enum Ty {
    Str,
    Bool,
    Int,
    Float,
    Table(&'static [Field]),
    ListStr,
    ListTable(&'static [Field]),
    ListEnum(&'static [&'static str], &'static str),
}

pub struct Field {
    pub name: &'static str,
    pub ty: Ty,
}

macro_rules! fields {
    ($($n:literal : $t:expr),* $(,)?) => { &[$(Field { name: $n, ty: $t }),*] };
}
use Ty::*;

const PROVIDER: &[Field] = fields!["orgId": Str, "shortName": Str, "dateUpdated": Str, "x_subShortName": Str];
const MEDIA: &[Field] = fields!["type": Str, "base64": Bool, "value": Str];
const DESCRIPTION: &[Field] = fields!["lang": Str, "value": Str, "supportingMedia": ListTable(MEDIA)];
const ROUTINE: &[Field] = fields!["name": Str];
const CHANGE: &[Field] = fields!["at": Str, "status": Str];
const VERSION: &[Field] = fields!["version": Str, "status": Str, "versionType": Str, "lessThan": Str, "lessThanOrEqual": Str, "changes": ListTable(CHANGE)];
const AFFECTED: &[Field] = fields![
    "vendor": Str, "product": Str, "collectionURL": Str, "packageName": Str, "cpes": ListStr, "modules": ListStr,
    "programFiles": ListStr, "programRoutines": ListTable(ROUTINE), "platforms": ListStr, "repo": Str,
    "defaultStatus": Str, "versions": ListTable(VERSION),
];
const REFERENCE: &[Field] = fields!["url": Str, "name": Str, "tags": ListStr];
const PT_DESC: &[Field] = fields!["lang": Str, "description": Str, "cweId": Str, "type": Str];
const PROBLEM: &[Field] = fields!["descriptions": ListTable(PT_DESC)];
const IMPACT: &[Field] = fields!["capecId": Str, "descriptions": ListTable(DESCRIPTION)];
const SCENARIO: &[Field] = fields!["lang": Str, "value": Str];
const CVSS3: &[Field] = fields![
    "version": Str, "vectorString": Str, "attackVector": Str, "attackComplexity": Str, "privilegesRequired": Str,
    "userInteraction": Str, "scope": Str, "confidentialityImpact": Str, "integrityImpact": Str,
    "availabilityImpact": Str, "baseScore": Float, "baseSeverity": Str, "exploitCodeMaturity": Str,
    "remediationLevel": Str, "reportConfidence": Str, "temporalScore": Float, "temporalSeverity": Str,
    "confidentialityRequirement": Str, "integrityRequirement": Str, "availabilityRequirement": Str,
    "modifiedAttackVector": Str, "modifiedAttackComplexity": Str, "modifiedPrivilegesRequired": Str,
    "modifiedUserInteraction": Str, "modifiedScope": Str, "modifiedConfidentialityImpact": Str,
    "modifiedIntegrityImpact": Str, "modifiedAvailabilityImpact": Str, "environmentalScore": Float,
    "environmentalSeverity": Str,
];
const CVSS2: &[Field] = fields![
    "version": Str, "vectorString": Str, "accessVector": Str, "accessComplexity": Str, "authentication": Str,
    "confidentialityImpact": Str, "integrityImpact": Str, "availabilityImpact": Str, "baseScore": Float,
    "exploitability": Str, "remediationLevel": Str, "reportConfidence": Str, "temporalScore": Float,
    "collateralDamagePotential": Str, "targetDistribution": Str, "confidentialityRequirement": Str,
    "integrityRequirement": Str, "availabilityRequirement": Str, "environmentalScore": Float,
];
const STRINGIFIED: &[Field] = fields!["data": Str];
const OTHER: &[Field] = fields!["type": Str, "content": Table(STRINGIFIED)];
const METRIC: &[Field] = fields![
    "format": Str, "scenarios": ListTable(SCENARIO), "cvssV3_1": Table(CVSS3), "cvssV3_0": Table(CVSS3),
    "cvssV2_0": Table(CVSS2), "other": Table(OTHER),
];
const TIMELINE: &[Field] = fields!["time": Str, "lang": Str, "value": Str];
const CREDIT: &[Field] = fields!["lang": Str, "value": Str, "user": Str, "type": Str];
const REMEDIATION: &[Field] = fields!["anyOf": ListStr, "products": ListStr, "type": Str];
const REMEDIATIONS: &[Field] = fields!["windows": ListTable(REMEDIATION)];
const TAX_REL: &[Field] = fields!["taxonomyId": Str, "relationshipName": Str, "relationshipValue": Str];
const TAXONOMY: &[Field] = fields!["taxonomyName": Str, "taxonomyVersion": Str, "taxonomyRelations": ListTable(TAX_REL)];
pub const CNA: &[Field] = fields![
    "providerMetadata": Table(PROVIDER), "dateAssigned": Str, "datePublic": Str, "title": Str,
    "descriptions": ListTable(DESCRIPTION), "affected": ListTable(AFFECTED), "problemTypes": ListTable(PROBLEM),
    "references": ListTable(REFERENCE), "impacts": ListTable(IMPACT), "metrics": ListTable(METRIC),
    "configurations": ListTable(DESCRIPTION), "workarounds": ListTable(DESCRIPTION), "solutions": ListTable(DESCRIPTION),
    "exploits": ListTable(DESCRIPTION), "timeline": ListTable(TIMELINE), "credits": ListTable(CREDIT),
    "source": Table(STRINGIFIED), "tags": ListStr, "taxonomyMappings": ListTable(TAXONOMY),
    "x_remediations": Table(REMEDIATIONS), "rejectedReasons": ListTable(DESCRIPTION), "replacedBy": ListStr,
];
pub const ADP: &[Field] = fields![
    "providerMetadata": Table(PROVIDER), "datePublic": Str, "title": Str,
    "descriptions": ListTable(DESCRIPTION), "affected": ListTable(AFFECTED), "problemTypes": ListTable(PROBLEM),
    "references": ListTable(REFERENCE), "impacts": ListTable(IMPACT), "metrics": ListTable(METRIC),
    "configurations": ListTable(DESCRIPTION), "workarounds": ListTable(DESCRIPTION), "solutions": ListTable(DESCRIPTION),
    "exploits": ListTable(DESCRIPTION), "timeline": ListTable(TIMELINE), "credits": ListTable(CREDIT),
    "source": Table(STRINGIFIED), "tags": ListStr, "taxonomyMappings": ListTable(TAXONOMY),
];
const CONTAINERS: &[Field] = fields!["cna": Table(CNA), "adp": ListTable(ADP)];
const METADATA: &[Field] = fields![
    "cveId": Str, "assignerOrgId": Str, "assignerShortName": Str, "requesterUserId": Str, "dateUpdated": Str,
    "serial": Int, "dateReserved": Str, "datePublished": Str, "state": Str, "dateRejected": Str,
];
pub const CVE_ENTRY: &[Field] = fields!["dataType": Str, "dataVersion": Str, "cveMetadata": Table(METADATA), "containers": Table(CONTAINERS)];

pub const ACTIONS: &[&str] = &[
    "replace_vendor", "replace_product", "replace_vendor_if_matches", "replace_product_if_matches",
    "set_version_if_matches", "replace_sw_edition_if_product_matches", "replace_msu_name_if_version_matches",
    "ignore", "check_hotfix", "replace_msu_name", "set_version_if_product_matches",
    "set_targethw_if_product_matches", "set_version_only_if_product_matches",
    "set_targethw_only_if_product_matches", "set_update_if_product_matches", "set_update_only_if_product_matches",
];
const T_SOURCE: &[Field] = fields!["vendor": Str, "product": Str, "version": Str, "update": Str, "target_hw": Str];
const T_ENTRY: &[Field] = fields!["vendor": Str, "product": Str, "version": Str, "update": Str, "msu_name": Str, "sw_edition": Str];
pub const TRANSLATION: &[Field] = fields!["action": ListEnum(ACTIONS, "Action"), "source": Table(T_SOURCE), "target": ListStr, "translation": ListTable(T_ENTRY)];

// ---- normalising --------------------------------------------------------------------------

/// Length of the compact, sorted-key JSON text of `v`.
fn clen(v: &Value) -> usize {
    match v {
        Value::Object(m) => 2 + m.len().saturating_sub(1) + m.iter().map(|(k, x)| Value::String(k.clone()).to_string().len() + 1 + clen(x)).sum::<usize>(),
        Value::Array(a) => 2 + a.len().saturating_sub(1) + a.iter().map(clen).sum::<usize>(),
        o => o.to_string().len(),
    }
}

fn token(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "true/false",
        Value::Number(n) if n.is_f64() => "decimal number",
        Value::Number(_) => "integer number",
        Value::String(_) => "text",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Position just after the first token of a value starting at `start`.
fn after(v: &Value, start: usize) -> usize {
    match v {
        Value::Object(_) | Value::Array(_) => start + 1,
        o => start + clen(o),
    }
}

struct SchemaErr(usize, String);
type R<T> = Result<T, SchemaErr>;

fn cannot(v: &Value, start: usize, ty: &str) -> SchemaErr {
    SchemaErr(after(v, start), format!("cannot store {} in a {ty} field", token(v)))
}

/// A 32-bit decimal as stored: its shortest text (so 6.1 stays 6.1); values that are not
/// finite (infinite, NaN, overflow) are stored as the integer 0.
fn f32_value(f: f32) -> Value {
    if !f.is_finite() {
        return Value::from(0);
    }
    format!("{f}").parse::<f64>().ok().and_then(Number::from_f64).map_or(Value::from(0), Value::Number)
}

fn is_plain_ascii(s: &str) -> bool {
    s.is_ascii() && !s.contains('\\')
}

fn norm_float(v: &Value, start: usize) -> R<Value> {
    match v {
        Value::Number(n) => Ok(f32_value(n.as_f64().unwrap_or(0.0) as f32)),
        Value::String(s) if is_plain_ascii(s) => {
            let t = s.trim_end_matches(' ');
            // `inf`, `nan` and `infinity` (any case) parse here and are stored as 0.
            t.parse::<f32>().map(f32_value).map_err(|_| SchemaErr(after(v, start), format!("invalid number: \"{t}\"")))
        }
        o => Err(cannot(o, start, "float")),
    }
}

fn norm_int(name: &str, v: &Value, start: usize) -> R<Value> {
    let fits = |n: Option<i64>| n.filter(|x| i32::try_from(*x).is_ok()).map(Value::from);
    match v {
        Value::Number(n) if n.is_f64() => Err(cannot(v, start, "int")),
        Value::Number(n) => fits(n.as_i64()).ok_or_else(|| SchemaErr(after(v, start), format!("value does not fit field {name}"))),
        // Any failure of a text (out of 32-bit range, backslash, not a number) is an invalid number.
        Value::String(s) => match s.trim_end_matches(' ').parse::<i64>().ok().filter(|_| is_plain_ascii(s)).and_then(|x| fits(Some(x))) {
            Some(x) => Ok(x),
            None => Err(SchemaErr(after(v, start), format!("invalid number: \"{s}\""))),
        },
        o => Err(cannot(o, start, "int")),
    }
}

fn norm_bool(v: &Value, start: usize) -> R<Value> {
    match v {
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::String(s) if s == "true" || s == "false" => Ok(Value::Bool(s == "true")),
        Value::Number(n) if !n.is_f64() => Ok(Value::Bool(n.as_i64().is_none_or(|x| x != 0))),
        o => Err(cannot(o, start, "bool")),
    }
}

fn norm_enum(names: &[&str], ename: &str, field: &str, v: &Value, start: usize) -> R<Value> {
    let name_of = |x: i64| usize::try_from(x).ok().and_then(|i| names.get(i)).map_or(Value::from(x), |n| Value::from(*n));
    match v {
        Value::String(s) if s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') => names
            .iter()
            .find(|n| *n == s)
            .map(|n| Value::from(*n))
            .ok_or_else(|| SchemaErr(after(v, start), format!("unknown name {s} for {ename}"))),
        Value::Number(n) if !n.is_f64() => match n.as_i64() {
            Some(x) if (-128..=127).contains(&x) => Ok(name_of(x)),
            Some(_) => Err(SchemaErr(after(v, start), format!("value does not fit field {field}"))),
            // Beyond 64-bit signed: a type mismatch.
            None => Err(cannot(v, start, "byte")),
        },
        // Other texts are read as an 8-bit number.
        Value::String(s) => match s.trim_end_matches(' ').parse::<i8>() {
            Ok(x) => Ok(name_of(i64::from(x))),
            Err(_) => Err(SchemaErr(after(v, start), format!("invalid number: \"{s}\""))),
        },
        o => Err(cannot(o, start, "byte")),
    }
}

fn norm_value(f: &Field, v: &Value, start: usize) -> R<Option<Value>> {
    let expected = |what: &str| SchemaErr(after(v, start), format!("expected {what}, found {}", token(v)));
    Ok(Some(match f.ty {
        Str | Table(_) | ListStr | ListTable(_) | ListEnum(..) if v.is_null() => return Ok(None),
        Str => match v {
            Value::String(_) => v.clone(),
            _ => return Err(expected("a text value")),
        },
        Float => norm_float(v, start)?,
        Int => norm_int(f.name, v, start)?,
        Bool => norm_bool(v, start)?,
        Table(t) => match v {
            Value::Object(_) => Value::Object(norm_table(t, v, start)?),
            _ => return Err(expected("an object")),
        },
        ListStr | ListTable(_) | ListEnum(..) => {
            let Value::Array(a) = v else { return Err(expected("an array")) };
            let mut out = Vec::with_capacity(a.len());
            let mut cur = start + 1;
            for x in a {
                let item = match f.ty {
                    ListStr => match x {
                        Value::String(_) => x.clone(),
                        _ => return Err(SchemaErr(after(x, cur), format!("expected a text value, found {}", token(x)))),
                    },
                    ListTable(t) => match x {
                        Value::Object(_) => Value::Object(norm_table(t, x, cur)?),
                        _ => return Err(SchemaErr(after(x, cur), format!("expected an object, found {}", token(x)))),
                    },
                    ListEnum(names, en) => norm_enum(names, en, f.name, x, cur)?,
                    _ => unreachable!(),
                };
                out.push(item);
                cur += clen(x) + 1;
            }
            Value::Array(out)
        }
    }))
}

fn norm_table(fields: &[Field], v: &Value, start: usize) -> R<Map<String, Value>> {
    let m = v.as_object().expect("object");
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    let mut out = Map::new();
    let mut cur = start + 1;
    for k in keys {
        let x = &m[k.as_str()];
        let vstart = cur + Value::String(k.clone()).to_string().len() + 1;
        let vend = vstart + clen(x);
        if k == "$schema" {
            if !x.is_string() {
                return Err(SchemaErr(after(x, vstart), format!("expected a text value, found {}", token(x))));
            }
        } else {
            let Some(f) = fields.iter().find(|f| f.name == k) else {
                return Err(SchemaErr(after(x, vstart), format!("unknown field: {k}")));
            };
            if let Some(nv) = norm_value(f, x, vstart)? {
                out.insert(k.clone(), nv);
            }
        }
        cur = vend + 1;
    }
    for f in fields {
        if out.contains_key(f.name) {
            continue;
        }
        let d = match f.ty {
            Int => Value::from(0),
            Float => Value::from(0.0),
            Bool => Value::Bool(false),
            _ => continue,
        };
        out.insert(f.name.to_string(), d);
    }
    Ok(out)
}

/// Normalises `input` with the root table `root`. Errors carry the byte column in the compact,
/// sorted-key text of the input.
pub fn normalize(root: &[Field], input: &Value) -> Result<Value, String> {
    if !input.is_object() {
        return Err(format!("line 1, column {}: expected an object, found {}", after(input, 0), token(input)));
    }
    norm_table(root, input, 0).map(Value::Object).map_err(|SchemaErr(c, m)| format!("line 1, column {c}: {m}"))
}

/// Decimal printed with up to 6 decimals, trailing zeros removed (one kept after the point).
pub fn float_text(f: f32) -> String {
    let s = format!("{f:.6}");
    let t = s.trim_end_matches('0');
    if t.ends_with('.') {
        format!("{t}0")
    } else {
        t.to_string()
    }
}

/// The stored record turned back into JSON for patching: decimals go through `float_text`.
pub fn text_form(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), text_form(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(text_form).collect()),
        Value::Number(n) if n.is_f64() => {
            let t = float_text(n.as_f64().unwrap_or(0.0) as f32);
            t.parse::<f64>().ok().and_then(Number::from_f64).map_or(v.clone(), Value::Number)
        }
        o => o.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::compact;
    use serde_json::json;

    #[test]
    fn defaults_and_enums() {
        let v = normalize(CVE_ENTRY, &json!({"cveMetadata":{"cveId":"CVE-1","dateRejected":null},"containers":{"cna":{"metrics":[{"cvssV3_1":{"baseScore":"7.5 "}}]}}})).unwrap();
        assert_eq!(v["cveMetadata"], json!({"cveId":"CVE-1","serial":0}));
        let c = &v["containers"]["cna"]["metrics"][0]["cvssV3_1"];
        assert_eq!(compact(c), r#"{"baseScore":7.5,"environmentalScore":0.0,"temporalScore":0.0}"#);
        let t = normalize(TRANSLATION, &json!({"action":["ignore",1],"target":["windows"]})).unwrap();
        assert_eq!(t["action"], json!(["ignore","replace_product"]));
        assert_eq!(ACTIONS[15], "set_update_only_if_product_matches");
        assert_eq!(CNA.len(), 22);
        assert_eq!(ADP.len(), 18);
        let f = normalize(CVE_ENTRY, &json!({"containers":{"cna":{"metrics":[{"cvssV3_0":{"baseScore":6.1}}]}}})).unwrap();
        assert_eq!(compact(&f["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]), "6.1");
    }

    #[test]
    fn error_positions() {
        assert_eq!(normalize(CVE_ENTRY, &json!({"x":1})).unwrap_err(), "line 1, column 6: unknown field: x");
        assert_eq!(
            normalize(CVE_ENTRY, &json!({"cveMetadata":{"cveId":"C","serial":1.5}})).unwrap_err(),
            "line 1, column 40: cannot store decimal number in a int field"
        );
        assert!(normalize(CVE_ENTRY, &json!({"cveMetadata":{"serial":null}})).unwrap_err().ends_with("cannot store null in a int field"));
        assert!(normalize(CVE_ENTRY, &json!({"dataType":1})).unwrap_err().ends_with("expected a text value, found integer number"));
        assert!(normalize(CVE_ENTRY, &json!({"containers":[]})).unwrap_err().ends_with("column 15: expected an object, found array"));
        assert!(normalize(CVE_ENTRY, &json!({"$schema":"x","dataType":"d"})).is_ok());
        assert!(normalize(TRANSLATION, &json!({"action":["nope"]})).unwrap_err().contains("unknown name nope for Action"));
        assert!(normalize(TRANSLATION, &json!({"action":[300]})).unwrap_err().contains("value does not fit field action"));
    }

    #[test]
    fn corrections_d10_d20_d49() {
        // D10: non-finite decimals are stored as the integer 0; inf/nan texts accepted.
        let m = |x: Value| normalize(CVE_ENTRY, &json!({"containers":{"cna":{"metrics":[{"cvssV3_1":{"baseScore":x}}]}}})).map(|v| compact(&v["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]));
        assert_eq!(m(json!("nan")).unwrap(), "0");
        assert_eq!(m(json!("Infinity ")).unwrap(), "0");
        assert_eq!(m(json!(1e39)).unwrap(), "0");
        assert!(m(json!("6.x  ")).unwrap_err().ends_with("invalid number: \"6.x\""));
        // D20: unknown key position after the first token of its value.
        assert_eq!(normalize(CVE_ENTRY, &json!({"zz":{"a":1}})).unwrap_err(), "line 1, column 7: unknown field: zz");
        // D49: integer texts out of range are invalid numbers; enumeration texts are 8-bit.
        assert!(normalize(CVE_ENTRY, &json!({"cveMetadata":{"serial":"99999999999"}})).unwrap_err().ends_with("invalid number: \"99999999999\""));
        assert!(normalize(TRANSLATION, &json!({"action":["300"]})).unwrap_err().ends_with("invalid number: \"300\""));
        assert!(normalize(TRANSLATION, &json!({"action":[18446744073709551615u64]})).unwrap_err().ends_with("cannot store integer number in a byte field"));
    }

    #[test]
    fn text_form_floats() {
        assert_eq!(float_text(6.3), "6.3");
        assert_eq!(float_text(10.0), "10.0");
        assert_eq!(float_text(0.0), "0.0");
        assert_eq!(compact(&text_form(&json!({"a":[7.25],"n":3}))), r#"{"a":[7.25],"n":3}"#);
    }
}
