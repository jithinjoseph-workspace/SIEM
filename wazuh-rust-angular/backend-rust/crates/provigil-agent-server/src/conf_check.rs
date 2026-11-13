//! The check of a group's `agent.conf` before the console saves it: readable XML, only
//! `<agent_config>` roots, only known sections, and valid `<localfile>` and `<socket>` sections.
//! The answer is the error text the console shows, or Ok.
//!
//! Only problems that make a section unusable fail the check; questionable values that have a
//! default (warnings) pass.

use provigil_daemon::xml::{self, Node};
use provigil_regex::{ExpType, Expression};

const FILE: &str = "agent.conf";

fn invalid_element(e: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{e}'.")
}

fn invalid_value(e: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{e}': {v}.")
}

/// The log formats a `<localfile>` may name (besides `multi-line:<lines>`).
const LOG_FORMATS: &[&str] = &[
    "syslog", "generic", "json", "snort-full", "snort-fast", "apache", "iis", "squid", "nmapg", "mysql_log", "ossecalert", "mssql_log", "postgresql_log", "djb-multilog", "syslog-pipe", "command",
    "full_command", "audit", "multi-line-regex", "eventlog", "eventchannel", "macos", "journald",
];

/// A leading whole number in base 10 (white space and a sign before it): the value and where
/// the digits end; (0, 0) when there are none.
fn leading_int(s: &str) -> (i64, usize) {
    let b = s.as_bytes();
    let mut i = b.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')).count();
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let start = i;
    let mut v: i128 = 0;
    while let Some(c) = b.get(i).filter(|c| c.is_ascii_digit()) {
        v = (v * 10 + (c - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if neg { -v } else { v };
    (v.clamp(i64::MIN as i128, i64::MAX as i128) as i64, i)
}

/// A leading unsigned number whose base follows its prefix (`0x` hex, `0` octal, else
/// decimal): the value (a minus sign wraps it; too large is the maximum) and the rest.
fn leading_unsigned(s: &str) -> (u64, &str) {
    let b = s.as_bytes();
    let mut i = b.iter().take_while(|c| **c == b' ' || (b'\t'..=b'\r').contains(c)).count();
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let (base, start) = match (b.get(i), b.get(i + 1), b.get(i + 2)) {
        (Some(b'0'), Some(b'x' | b'X'), Some(h)) if h.is_ascii_hexdigit() => (16u64, i + 2),
        (Some(b'0'), ..) => (8, i),
        _ => (10, i),
    };
    let mut j = start;
    let mut v: u64 = 0;
    let mut too_large = false;
    while let Some(d) = b.get(j).and_then(|c| (*c as char).to_digit(16)).map(u64::from).filter(|d| *d < base) {
        match v.checked_mul(base).and_then(|x| x.checked_add(d)) {
            Some(x) => v = x,
            None => too_large = true,
        }
        j += 1;
    }
    if j == start && base != 8 {
        return (0, s);
    }
    if too_large {
        return (u64::MAX, &s[j..]);
    }
    (if neg { v.wrapping_neg() } else { v }, &s[j..])
}

/// A time unit after a number: w, d, h, m or s.
fn unit(rest: &str, empty_ok: bool) -> bool {
    match rest.as_bytes().first() {
        Some(b'w' | b'd' | b'h' | b'm' | b's') => true,
        None => empty_ok,
        _ => false,
    }
}

/// One `<localfile>`. Err: why it cannot be used. Problems that do not stop it go to `noted`.
fn localfile(fields: &[Node], noted: &mut Vec<String>) -> Result<(), String> {
    // the file is the last <location> or <command>
    let (mut format, mut file, mut multiline, mut command) = (None::<&str>, None::<&str>, false, false);
    for n in fields {
        let (el, v) = (n.name.as_str(), n.content.as_str());
        let is = |name: &str| el.eq_ignore_ascii_case(name);
        match el {
            "only-future-events" | "query" | "target" | "out_format" => {}
            "reconnect_time" => {
                let (n, rest) = leading_unsigned(v);
                if n as i32 != 0 && !unit(rest, false) {
                    return Err(invalid_value(el, v));
                }
            }
            "label" => match n.attribute("key") {
                Some("") => return Err("Label with empty key.".into()),
                // reserved for internal use: skipped
                Some(k) if k.starts_with('_') => {}
                Some(_) => {}
                None => return Err("Expected 'key' attribute for label.".into()),
            },
            "command" => (file, command) = (Some(v), true),
            "frequency" => {
                if v != "hourly" && v != "daily" && !provigil_regex::str_is_num(v) {
                    return Err(invalid_value(el, v));
                }
            }
            "location" => file = Some(v),
            "age" => {
                let (n, rest) = leading_unsigned(v);
                if n as u32 == 0 || n as u32 == u32::MAX || !unit(rest, true) {
                    return Err("Invalid age for localfile".into());
                }
            }
            _ if is("log_format") => {
                format = Some(v);
                if !LOG_FORMATS.contains(&v) {
                    let lines = v.strip_prefix("multi-line").map(|r| r.trim_start_matches(' ')).and_then(|r| r.strip_prefix(':')).map(leading_int);
                    if !matches!(lines, Some((n, used)) if used > 0 && n >= 1) {
                        return Err(invalid_value(el, v));
                    }
                }
            }
            _ if is("multiline_regex") => {
                // only the first non-empty one is used
                if !v.is_empty() && !multiline {
                    if Expression::compile(ExpType::Pcre2, v, 0).is_err() {
                        return Err(format!("(1967): Syntax error on multiline_regex: '{v}'"));
                    }
                    multiline = true;
                }
            }
            _ if is("exclude") || is("alias") => {}
            _ if is("ignore_binaries") => {
                if v != "yes" && v != "no" {
                    return Err(invalid_value(el, v));
                }
            }
            _ if is("ignore") || is("restrict") => {
                let which = if is("ignore") { "ignore" } else { "restrict" };
                let bad = || format!("(1975): Syntax error on regex {which}: '{v}'");
                let kind = match n.attributes.first() {
                    None => ExpType::Pcre2,
                    Some((a, _)) if a != "type" => return Err(bad()),
                    Some((_, t)) if t.eq_ignore_ascii_case("osregex") => ExpType::OsRegex,
                    Some((_, t)) if t.eq_ignore_ascii_case("osmatch") => ExpType::OsMatch,
                    // pcre2, or an unknown type read as pcre2
                    Some(_) => ExpType::Pcre2,
                };
                if Expression::compile(kind, v, 0).is_err() {
                    return Err(bad());
                }
            }
            _ if is("filter") => {
                // a journal filter that cannot be added drops the whole section, without error
                let field = n.attribute("field").unwrap_or("");
                if field.is_empty() || v.is_empty() || Expression::compile(ExpType::Pcre2, v, 0).is_err() {
                    return Ok(());
                }
            }
            _ => return Err(invalid_element(el)),
        }
    }
    let Some(format) = format else { return Err("(1901): Missing 'log_format' element.".into()) };
    if file.is_none() && format != "macos" && format != "journald" {
        return Err("(1902): Missing 'location' element.".into());
    }
    if format == "multi-line-regex" && !multiline {
        return Err("(1968): Missing 'multiline_regex' element.".into());
    }
    if format == "eventlog" && !matches!(file, Some("Application" | "System" | "Security")) {
        return Ok(());
    }
    if (format == "command" || format == "full_command") && !command {
        noted.push("Missing 'command' argument. This option will be ignored.".into());
    }
    Ok(())
}

/// One `<socket>`. Err: why it cannot be used.
fn socket(fields: &[Node]) -> Result<(), String> {
    let (mut name, mut location) = (None::<&str>, None::<&str>);
    for n in fields {
        let v = n.content.as_str();
        match n.name.as_str() {
            "name" if v == "agent" => return Err("Invalid socket name 'agent'.".into()),
            "name" => name = Some(v),
            "location" => location = Some(v),
            "mode" if !v.eq_ignore_ascii_case("tcp") && !v.eq_ignore_ascii_case("udp") => {
                return Err(format!("Socket type '{v}' is not valid at <{}>. Should be 'udp' or 'tcp'.", n.name));
            }
            "mode" | "prefix" => {}
            other => return Err(invalid_element(other)),
        }
    }
    if name.is_none_or(str::is_empty) {
        return Err("(1954): Missing field 'name' for socket.".into());
    }
    if location.is_none_or(str::is_empty) {
        return Err("(1955): Missing field 'location' for socket.".into());
    }
    Ok(())
}

/// Checks an `agent.conf`; Err: the text to show.
pub fn check(text: &str) -> Result<(), String> {
    let roots = xml::parse(text.as_bytes()).map_err(|e| format!("XML error (line {}): {}", e.line, e.message))?;
    // problems that do not fail the check are still listed with one that does
    let mut errors: Vec<String> = Vec::new();
    for root in &roots {
        if root.name != "agent_config" {
            errors.push(invalid_element(&root.name));
            return Err(errors.join(" "));
        }
        for (a, _) in &root.attributes {
            if !matches!(a.as_str(), "name" | "os" | "profile" | "overwrite") {
                errors.push(format!("(1233): Invalid attribute '{a}' in the configuration: '{FILE}'."));
            }
        }
        for s in &root.children {
            let has = !s.children.is_empty();
            let outcome = if !provigil_daemon::sections::known(&s.name, has) {
                Err(invalid_element(&s.name))
            } else {
                match s.name.as_str() {
                    "localfile" => localfile(&s.children, &mut errors),
                    "socket" => socket(&s.children),
                    _ => Ok(()),
                }
            };
            if let Err(m) = outcome {
                errors.push(m);
                errors.push(format!("(1202): Configuration error at '{FILE}'."));
                return Err(errors.join(" "));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert_eq!(check("<agent_config>\n  <localfile><location>/var/log/x</location><log_format>syslog</log_format></localfile>\n</agent_config>\n"), Ok(()));
        assert_eq!(check("<agent_config><localfile><location>x</location></localfile></agent_config>"), Err("(1901): Missing 'log_format' element. (1202): Configuration error at 'agent.conf'.".into()));
        assert_eq!(check("<ossec_config/>"), Err("(1230): Invalid element in the configuration: 'ossec_config'.".into()));
        assert_eq!(check("<agent_config><a>"), Err("XML error (line 1): XMLERR: End of file and some elements were not closed.".into()));
        assert_eq!(check("<agent_config os=\"Linux\" x=\"1\"><socket><name>s</name></socket></agent_config>"), Err("(1233): Invalid attribute 'x' in the configuration: 'agent.conf'. (1955): Missing field 'location' for socket. (1202): Configuration error at 'agent.conf'.".into()));
        assert_eq!((leading_unsigned("0x1fz"), leading_unsigned("010"), leading_unsigned("-1").0), ((31, "z"), (8, ""), u64::MAX));
    }
}
