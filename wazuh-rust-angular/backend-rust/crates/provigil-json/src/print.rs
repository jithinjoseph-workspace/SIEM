//! Writing documents.

use crate::Json;

/// `indent`: None for compact output, else the depth of `v` in an indented document.
pub(crate) fn value(v: &Json, out: &mut Vec<u8>, indent: Option<usize>) {
    match v {
        Json::Null => out.extend_from_slice(b"null"),
        Json::False => out.extend_from_slice(b"false"),
        Json::True => out.extend_from_slice(b"true"),
        Json::Number { double, int } => number(*double, *int, out),
        Json::String(s) => string(s, out),
        Json::Array(items) => {
            out.push(b'[');
            for (i, e) in items.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(if indent.is_some() { b", " } else { b"," });
                }
                value(e, out, indent.map(|d| d + 1));
            }
            out.push(b']');
        }
        Json::Object(members) => {
            out.push(b'{');
            let inner = indent.map(|d| d + 1);
            if let Some(d) = inner {
                out.push(b'\n');
                for (i, (k, v)) in members.iter().enumerate() {
                    out.resize(out.len() + d, b'\t');
                    string(k, out);
                    out.extend_from_slice(b":\t");
                    value(v, out, inner);
                    if i + 1 < members.len() {
                        out.push(b',');
                    }
                    out.push(b'\n');
                }
                out.resize(out.len() + d - 1, b'\t');
            } else {
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    string(k, out);
                    out.push(b':');
                    value(v, out, None);
                }
            }
            out.push(b'}');
        }
    }
}

/// A quoted string, up to its first zero byte. Other bytes below 0x20 are escaped (the usual
/// short forms where they exist); bytes from 0x7f up are written as they are.
fn string(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &c in s.iter().take_while(|&&c| c != 0) {
        let short = match c {
            b'"' => b'"',
            b'\\' => b'\\',
            0x08 => b'b',
            0x0c => b'f',
            b'\n' => b'n',
            b'\r' => b'r',
            b'\t' => b't',
            c if c < 0x20 => {
                out.extend_from_slice(format!("\\u{c:04x}").as_bytes());
                continue;
            }
            c => {
                out.push(c);
                continue;
            }
        };
        out.extend_from_slice(&[b'\\', short]);
    }
    out.push(b'"');
}

/// An integer when the value equals its i32 view; else 15 significant digits when they read
/// back to the value (within one unit of relative precision), else 17. NaN and infinities: null.
fn number(d: f64, int: i32, out: &mut Vec<u8>) {
    let text = if !d.is_finite() {
        "null".to_string()
    } else if d == int as f64 {
        int.to_string()
    } else {
        let short = general(d, 15);
        let back: f64 = short.parse().unwrap_or(f64::NAN);
        if (back - d).abs() <= d.abs().max(back.abs()) * f64::EPSILON {
            short
        } else {
            general(d, 17)
        }
    };
    out.extend_from_slice(text.as_bytes());
}

/// `d` with `digits` significant digits in the shorter of fixed and exponent notation, trailing
/// zeros removed: exponent notation when the decimal exponent is below -4 or at least `digits`,
/// written `e±XX` (at least two exponent digits). Ties round to even, on the exact binary value.
fn general(d: f64, digits: usize) -> String {
    if d == 0.0 {
        return if d.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    // Rust's exact formatting: correctly rounded, ties to even
    let sci = format!("{:.*e}", digits - 1, d);
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mantissa) = mantissa.strip_prefix('-').map_or(("", mantissa), |m| ("-", m));
    let all: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if exp < -4 || exp >= digits as i32 {
        let (first, rest) = all.split_at(1);
        let rest = rest.trim_end_matches('0');
        let dot = if rest.is_empty() { "" } else { "." };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{first}{dot}{rest}e{esign}{:02}", exp.abs())
    } else if exp >= 0 {
        let (int, frac) = all.split_at(exp as usize + 1);
        let frac = frac.trim_end_matches('0');
        let dot = if frac.is_empty() { "" } else { "." };
        format!("{sign}{int}{dot}{frac}")
    } else {
        let zeros = "0".repeat((-exp - 1) as usize);
        let frac = all.trim_end_matches('0');
        format!("{sign}0.{zeros}{frac}")
    }
}

/// Six decimals (`nan`, `-nan`, `inf`, `-inf` for those values).
pub fn fmt_f6(v: f64) -> String {
    match v {
        v if v.is_nan() => if v.is_sign_negative() { "-nan" } else { "nan" }.to_string(),
        v if v.is_infinite() => if v < 0.0 { "-inf" } else { "inf" }.to_string(),
        v => format!("{v:.6}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        for (v, want) in [(2.5, "2.5"), (0.1, "0.1"), (1e20, "1e+20"), (1.5e-7, "1.5e-07"), (0.0001, "0.0001"), (123456789012.5, "123456789012.5"), (-3.25, "-3.25"), (1e300, "1e+300"), (5e-324, "4.94065645841247e-324")] {
            let mut o = Vec::new();
            number(v, crate::clamp_i32(v), &mut o);
            assert_eq!(String::from_utf8(o).unwrap(), want, "{v}");
        }
        assert_eq!(general(123456789012345.5, 15), "123456789012346");
        assert_eq!(general(123456789012344.5, 15), "123456789012344");
        assert_eq!(fmt_f6(1.0 / 3.0), "0.333333");
    }
}
