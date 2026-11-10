//! Checks every recorded case in specs/vectors/siem-regex, including the items the spec listed as
//! unused (section 1.2).

use provigil_regex::expression::{Expression, ExpressionKind};
use provigil_regex::os_ip::{atoi, cidr_to_str, expand_ipv6, get_ipv4_from_ipv6};
use provigil_regex::strings::str_break_bytes;
use provigil_regex::*;
use serde_json::Value;
use std::path::PathBuf;

const SHOWN: usize = 15;

#[test]
fn public_surface() {
    fn shareable<T: Clone + Send + Sync>() {}
    shareable::<OsRegex>();
    shareable::<OsMatch>();
    shareable::<Expression>();
    assert_eq!((OS_RETURN_SUBSTRING, OS_CASE_SENSITIVE, OS_PATTERN_MAXSIZE), (128, 256, 20480));
    assert_eq!(
        (expression::OSMATCH_STR, expression::OSREGEX_STR, expression::PCRE2_STR, expression::STRING_STR),
        ("osmatch", "osregex", "pcre2", "string")
    );
    let codes = [
        RegexError::PatternNull,
        RegexError::MaxSize,
        RegexError::OutOfMemory,
        RegexError::StrNull,
        RegexError::BadRegex,
        RegexError::BadParenthesis,
    ];
    assert_eq!(codes.map(|e| e as i32), [2, 3, 4, 5, 6, 7]);
    for (name, t) in [("OSMATCH", Some(ExpType::OsMatch)), ("osRegex", Some(ExpType::OsRegex)), ("PCRE2", Some(ExpType::Pcre2))] {
        assert_eq!(ExpType::from_attr(name), t);
    }
    assert_eq!((ExpType::from_attr("string"), ExpType::from_attr("")), (None, None));
    assert_eq!(os_regex::OS_RETURN_SUBSTRING, OS_RETURN_SUBSTRING);
    assert!(os_match::os_word_match("a|b", "xb"));
    assert_eq!(strings::str_break(',', "a,b", 2), Some(vec!["a".to_string(), "b".to_string()]));
    assert!(os_match::os_match2("a", "a") && os_regex::os_regex("a", "a"));
    assert!(os_ip::is_valid_ip("1.2.3.4").1.is_some());
}

#[test]
fn pattern_length_limit() {
    let at_limit = "a".repeat(OS_PATTERN_MAXSIZE);
    let over = "a".repeat(OS_PATTERN_MAXSIZE + 1);
    assert!(OsRegex::compile(&at_limit, 0).is_ok() && OsMatch::compile(&at_limit, 0).is_ok());
    assert_eq!(OsRegex::compile(&over, 0).err(), Some(RegexError::MaxSize));
    assert_eq!(OsMatch::compile(&over, 0).err(), Some(RegexError::MaxSize));
}

fn load(name: &str) -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors/siem-regex").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(unhex).collect()
}

fn run(name: &str, check: impl Fn(&Value) -> Option<Result<(), String>>) {
    let cases = load(name);
    let (mut passed, mut skipped, mut failed) = (0, 0, Vec::new());
    for case in &cases {
        match check(case) {
            None => skipped += 1,
            Some(Ok(())) => passed += 1,
            Some(Err(why)) => failed.push(format!("{why}\n    case: {}", short(case))),
        }
    }
    println!("{name}: {passed}/{} passed, {skipped} skipped, {} failed", cases.len() - skipped, failed.len());
    for f in failed.iter().take(SHOWN) {
        println!("  {f}");
    }
    assert!(failed.is_empty(), "{name}: {} of {} cases failed", failed.len(), cases.len());
}

fn short(case: &Value) -> String {
    case.to_string().chars().take(300).collect()
}

fn check_eq<T: PartialEq + std::fmt::Debug>(what: &str, got: T, want: T) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {got:?}, want {want:?}"))
    }
}

#[test]
fn osregex() {
    run("osregex.json", |c| {
        let pattern = c["pattern"].as_str().unwrap();
        let flags = c["flags"].as_u64().unwrap() as u32;
        let r = &c["result"];
        Some((|| {
            let compiled = OsRegex::compile(pattern, flags);
            if let Some(code) = r["code"].as_i64() {
                return check_eq("error", compiled.err().map(|e| e as i64), Some(code));
            }
            let re = compiled.map_err(|e| format!("compile: {e:?}"))?;
            check_eq("raw", re.raw(), pattern)?;
            check_eq("has_sub_strings", re.has_sub_strings(), r["has_sub_strings"].as_bool().unwrap())?;
            let subject = unhex(&c["subject_hex"]);
            let got = re.execute_bytes(&subject);
            if let Ok(text) = std::str::from_utf8(&subject) {
                check_eq("execute", re.execute(text), got.clone())?;
                check_eq("is_match", re.is_match(text), got.is_some())?;
            }
            if !r["match"].as_bool().unwrap() {
                return check_eq("match", got, None);
            }
            let got = got.ok_or("no match, want one")?;
            check_eq("end", got.end as i64, r["end"].as_i64().unwrap())?;
            let subs = hex_list(&r["subs_hex"]);
            let lossy: Vec<String> = subs.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            check_eq("sub_strings", &got.sub_strings, &lossy)?;
            check_eq("sub_bytes", got.sub_bytes, subs)
        })())
    });
}

#[test]
fn osmatch() {
    run("osmatch.json", |c| {
        let pattern = c["pattern"].as_str().unwrap();
        let flags = c["flags"].as_u64().unwrap() as u32;
        let r = &c["result"];
        Some((|| {
            let compiled = OsMatch::compile(pattern, flags);
            if let Some(code) = r["code"].as_i64() {
                return check_eq("error", compiled.err().map(|e| e as i64), Some(code));
            }
            let m = compiled.map_err(|e| format!("compile: {e:?}"))?;
            check_eq("raw", m.raw(), pattern)?;
            check_eq("negated", m.is_negated(), r["negated"].as_bool().unwrap())?;
            let want = hex_list(&r["patterns_hex"]);
            let got: Vec<Vec<u8>> = m.patterns().iter().map(|p| p.to_vec()).collect();
            check_eq("patterns", got, want)?;
            let subject = unhex(&c["subject_hex"]);
            check_eq("match", m.is_match_bytes(&subject), r["match"].as_bool().unwrap())?;
            if let Ok(text) = std::str::from_utf8(&subject) {
                check_eq("is_match", m.is_match(text), r["match"].as_bool().unwrap())?;
            }
            Ok(())
        })())
    });
}

#[test]
fn word_match_and_oneshot() {
    run("word_match_and_oneshot.json", |c| {
        let (p, s) = (c["pattern"].as_str().unwrap(), c["subject"].as_str().unwrap());
        let got = match c["fn"].as_str().unwrap() {
            "os_word_match" => os_word_match(p, s),
            "os_regex" => os_regex(p, s),
            "os_match2" => os_match2(p, s),
            other => return Some(Err(format!("unknown fn {other}"))),
        };
        Some(check_eq("result", got, c["result"].as_bool().unwrap()))
    });
}

fn exp_type(name: &str) -> ExpType {
    match name {
        "OsRegex" => ExpType::OsRegex,
        "OsMatch" => ExpType::OsMatch,
        "String" => ExpType::String,
        "OsIpArray" => ExpType::OsIpArray,
        "Pcre2" => ExpType::Pcre2,
        other => panic!("unknown type {other}"),
    }
}

fn ip_texts(e: &Option<Expression>) -> Option<Vec<String>> {
    match e {
        Some(Expression { kind: ExpressionKind::OsIpArray(list), .. }) => {
            Some(list.iter().map(|ip| ip.ip.clone()).collect())
        }
        _ => None,
    }
}

fn add_osip_case(c: &Value) -> Result<(), String> {
    let mut e = match c["add_osip_start"].as_str().unwrap() {
        "none" => None,
        "osmatch" => Some(Expression::compile(ExpType::OsMatch, "abc", 0).unwrap()),
        other => return Err(format!("unknown start {other}")),
    };
    for step in c["steps"].as_array().unwrap() {
        let added = Expression::add_osip(&mut e, step["add"].as_str().unwrap());
        check_eq("add ok", added.is_ok(), step["ok"].as_bool().unwrap())?;
        check_eq("none", e.is_none(), step["now_none"].as_bool().unwrap())?;
        let want: Option<Vec<String>> = serde_json::from_value(step["now_ips"].clone()).unwrap();
        check_eq("ips", ip_texts(&e), want)?;
        let want_type = step["now_type"].as_str().map(exp_type);
        check_eq("type", e.as_ref().map(|x| x.exp_type()), want_type)?;
    }
    check_eq("pattern", e.as_ref().and_then(|x| x.pattern()), c["pattern_fn"].as_str())?;
    for s in c["subjects"].as_array().unwrap() {
        let text = s["subject"].as_str().unwrap();
        let got = e.as_ref().map(|x| x.matches(text).matched);
        check_eq(text, got, s["matched"].as_bool())?;
    }
    Ok(())
}

fn compile_case(c: &Value) -> Result<(), String> {
    let pattern = c["pattern"].as_str().unwrap();
    let flags = c["flags"].as_u64().unwrap() as u32;
    let compiled = Expression::compile(exp_type(c["type"].as_str().unwrap()), pattern, flags);
    if c["compile"] != "ok" {
        return match (compiled, c["compile"]["error"].as_str().unwrap()) {
            (Err(err @ ExpressionError::Regex(e)), "regex") => {
                check_eq("code", e as i64, c["compile"]["code"].as_i64().unwrap())?;
                check_eq("display", err.to_string().as_str(), c["compile"]["display"].as_str().unwrap())
            }
            (Err(err @ ExpressionError::InvalidIp(_)), "invalid_ip") => {
                check_eq("display", err.to_string().as_str(), c["compile"]["display"].as_str().unwrap())
            }
            (Err(ExpressionError::Pcre2(_)), "pcre2") => Ok(()),
            (got, want) => Err(format!("compile: got {:?}, want {want}", got.err())),
        };
    }
    let e = compiled.map_err(|e| format!("compile: {e:?}"))?;
    check_eq("negate", e.negate, false)?;
    check_eq("exp_type", e.exp_type(), exp_type(c["type"].as_str().unwrap()))?;
    check_eq("pattern", e.pattern(), c["pattern_fn"].as_str())?;
    check_eq("type_str", e.type_str(), c["type_str"].as_str())?;
    for s in c["subjects"].as_array().unwrap() {
        let subject = unhex(&s["subject_hex"]);
        let want = &s["match_bytes"];
        let mut captures = vec![b"PRIOR".to_vec()];
        let (matched, end) = e.match_bytes(&subject, Some(&mut captures));
        check_eq("matched", matched, want["matched"].as_bool().unwrap())?;
        check_eq("end", end.map(|n| n as i64), want["end"].as_i64())?;
        check_eq("captures", captures, hex_list(&want["captures_after_hex"]))?;
        if let Some(m) = s.get("matches_str") {
            let text = std::str::from_utf8(&subject).map_err(|e| e.to_string())?;
            let got = e.matches(text);
            check_eq("matches", got.matched, m["matched"].as_bool().unwrap())?;
            check_eq("matches end", got.end_match.map(|n| n as i64), m["end_match"].as_i64())?;
            let subs: Vec<String> = serde_json::from_value(m["sub_strings"].clone()).unwrap();
            check_eq("matches subs", got.sub_strings, subs)?;
            let mut negated = e.clone();
            negated.negate = true;
            check_eq("is_match", (e.is_match(text), negated.is_match(text)), (got.matched, !got.matched))?;
        }
    }
    Ok(())
}

#[test]
fn expression() {
    run("expression.json", |c| Some(if c.get("steps").is_some() { add_osip_case(c) } else { compile_case(c) }));
}

fn entry(v: &Value) -> OsIp {
    let net = &v["net"];
    let bytes = |k: &str| hex::decode(net[k].as_str().unwrap()).unwrap();
    let parsed = if net.get("v4_addr").is_some() {
        let word = |k: &str| u32::from_ne_bytes(bytes(k).try_into().unwrap());
        IpNet::V4 { ip_address: word("v4_addr"), netmask: word("v4_mask") }
    } else {
        IpNet::V6 {
            ip_address: bytes("v6_addr").try_into().unwrap(),
            netmask: bytes("v6_mask").try_into().unwrap(),
        }
    };
    OsIp { ip: v["ip"].as_str().unwrap().to_string(), net: parsed, is_ipv6: v["is_ipv6"].as_bool().unwrap() }
}

#[test]
fn ip() {
    run("ip.json", |c| {
        let text = |k: &str| c[k].as_str().unwrap();
        Some(match text("fn") {
            "is_valid_ip" => (|| {
                let (code, parsed) = is_valid_ip(text("input"));
                check_eq("code", i64::from(code), c["code"].as_i64().unwrap())?;
                let want = c.get("parsed").filter(|p| !p.is_null());
                check_eq("parsed", parsed.clone(), want.map(entry))?;
                if let (Some(got), Some(want)) = (parsed, want) {
                    check_eq("cidr", cidr_to_str(&got).as_deref(), want["cidr_to_str"].as_str())?;
                    check_eq("negated", got.negated(), want["negated"].as_bool().unwrap())?;
                }
                Ok(())
            })(),
            "get_ipv4_from_ipv6" => {
                check_eq("result", get_ipv4_from_ipv6(text("input")).as_deref(), c["result"].as_str())
            }
            "expand_ipv6" => check_eq("result", expand_ipv6(text("input")).as_deref(), c["result"].as_str()),
            "atoi" => check_eq("result", i64::from(atoi(text("input"))), c["result"].as_i64().unwrap()),
            "ip_found" => {
                let e = entry(&c["entry"]);
                check_eq("negated", e.negated(), c["entry"]["negated"].as_bool().unwrap())
                    .and_then(|()| check_eq("result", ip_found(text("target"), &e), c["result"].as_bool().unwrap()))
            }
            "ip_found_list" => {
                let list: Vec<OsIp> = c["list"].as_array().unwrap().iter().map(entry).collect();
                check_eq("result", ip_found_list(text("target"), &list), c["result"].as_bool().unwrap())
            }
            other => Err(format!("unknown fn {other}")),
        })
    });
}

#[test]
fn strings() {
    run("strings.json", |c| {
        let size = c["size"].as_u64().unwrap_or(0) as usize;
        Some(match c["fn"].as_str().unwrap() {
            "str_is_num" => check_eq("result", str_is_num(c["input"].as_str().unwrap()), c["result"].as_bool().unwrap()),
            "str_starts_with" => {
                let (s, p) = (c["s"].as_str().unwrap(), c["pattern"].as_str().unwrap());
                check_eq("result", str_starts_with(s, p), c["result"].as_bool().unwrap())
            }
            "str_how_closed_match" => {
                let (a, b) = (c["a"].as_str().unwrap(), c["b"].as_str().unwrap());
                check_eq("result", str_how_closed_match(a, b) as u64, c["result"].as_u64().unwrap())
            }
            "str_break" => {
                let sep = c["sep"].as_str().unwrap().chars().next().unwrap();
                let want: Option<Vec<String>> = serde_json::from_value(c["result"].clone()).unwrap();
                check_eq("result", str_break(sep, c["input"].as_str().unwrap(), size), want)
            }
            "str_break_bytes" => {
                let want = (!c["result_hex"].is_null()).then(|| hex_list(&c["result_hex"]));
                let got = str_break_bytes(unhex(&c["sep_hex"])[0], &unhex(&c["input_hex"]), size);
                check_eq("result", got, want)
            }
            "is_valid_hostname_char" => {
                let b = c["byte"].as_u64().unwrap() as u8;
                check_eq("result", is_valid_hostname_char(b), c["result"].as_bool().unwrap()).and_then(|()| {
                    check_eq("map", maps::HOSTNAME_MAP[b as usize] == 1, c["hostname_map_is_1"].as_bool().unwrap())
                })
            }
            other => Err(format!("unknown fn {other}")),
        })
    });
}

#[test]
fn tables() {
    run("tables.json", |c| {
        Some(match c["table"].as_str().unwrap() {
            "osregex_class" => {
                let escape = c["escape"].as_str().unwrap();
                let members: Vec<u64> = c["member_bytes"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap()).collect();
                let row = &maps::REGEXMAP[c["code"].as_u64().unwrap() as usize];
                let in_table = (0..=255u8).try_for_each(|b| {
                    check_eq("table", row[b as usize] == 1, members.contains(&u64::from(b)))
                });
                if in_table.is_err() || !escape.starts_with('\\') {
                    return Some(in_table);
                }
                let re = OsRegex::compile(escape, 0).unwrap();
                // Byte 0 ends a subject, so it can never reach the matcher.
                (1..=255u8).try_for_each(|b| {
                    check_eq(escape, re.execute_bytes(&[b]).is_some(), members.contains(&u64::from(b)))
                })
            }
            "case_fold" => c["changed"].as_array().unwrap().iter().try_for_each(|pair| {
                let (upper, lower) = (pair[0].as_u64().unwrap() as u8, pair[1].as_u64().unwrap() as u8);
                let re = OsRegex::compile(&(lower as char).to_string(), 0).unwrap();
                check_eq("fold", re.execute_bytes(&[upper]).is_some(), true)?;
                check_eq("charmap", maps::CHARMAP[upper as usize], lower)
            }),
            "hostname_value" => {
                let want: Vec<u8> = c["values"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
                check_eq("hostname map", maps::HOSTNAME_MAP.to_vec(), want)
            }
            other => Err(format!("unknown table {other}")),
        })
    });
}
