//! C number conversions cJSON relies on: `strtod` (longest valid decimal
//! prefix) and `printf("%1.<p>g")`.

/// `strtod` restricted to the decimal syntax cJSON can hand it
/// (`[+-]?digits[.digits][(e|E)[+-]?digits]`, with the glibc leniency that
/// `"1."` and `".5"` are valid). Returns the value and the bytes consumed, or
/// `None` when no conversion is possible.
pub fn strtod_prefix(s: &[u8]) -> Option<(f64, usize)> {
    let mut i = 0;
    // leading whitespace (strtod skips it; cJSON never passes any)
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let start = i;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        i += 1;
    }
    let int_start = i;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i - int_start;
    let mut frac_digits = 0;
    if i < s.len() && s[i] == b'.' {
        let j = i + 1;
        let mut k = j;
        while k < s.len() && s[k].is_ascii_digit() {
            k += 1;
        }
        frac_digits = k - j;
        if int_digits > 0 || frac_digits > 0 {
            i = k;
        }
    }
    if int_digits == 0 && frac_digits == 0 {
        return None;
    }
    let mantissa_end = i;
    if i < s.len() && (s[i] == b'e' || s[i] == b'E') {
        let mut k = i + 1;
        if k < s.len() && (s[k] == b'+' || s[k] == b'-') {
            k += 1;
        }
        let ds = k;
        while k < s.len() && s[k].is_ascii_digit() {
            k += 1;
        }
        if k > ds {
            i = k;
        }
    }
    // Normalise for Rust's parser: "1." -> "1.0", ".5" -> "0.5", "1.e5" -> "1.0e5"
    let mut norm = String::with_capacity(i - start + 2);
    let txt = std::str::from_utf8(&s[start..i]).ok()?;
    let (mant, exp) = txt.split_at(mantissa_end - start);
    let (sign, digits) = match mant.as_bytes().first() {
        Some(b'+') => ("", &mant[1..]),
        Some(b'-') => ("-", &mant[1..]),
        _ => ("", mant),
    };
    norm.push_str(sign);
    if digits.starts_with('.') {
        norm.push('0');
    }
    norm.push_str(digits);
    if digits.ends_with('.') {
        norm.push('0');
    }
    norm.push_str(exp);
    let v: f64 = norm.parse().ok()?;
    Some((v, i))
}

/// Round the decimal digit string `digits` (no leading zeros, value =
/// 0.d1d2... * 10^exp10) to `p` significant digits, round-half-even.
fn round_digits(digits: &[u8], exp10: i32, p: usize) -> (Vec<u8>, i32) {
    if digits.len() <= p {
        let mut d = digits.to_vec();
        d.resize(p, b'0');
        return (d, exp10);
    }
    let mut d = digits[..p].to_vec();
    let rest = &digits[p..];
    let first = rest[0];
    let round_up = if first > b'5' {
        true
    } else if first < b'5' {
        false
    } else if rest[1..].iter().any(|&c| c != b'0') {
        true
    } else {
        // exact tie: round half to even
        (d[p - 1] - b'0') % 2 == 1
    };
    let mut exp10 = exp10;
    if round_up {
        let mut k = p;
        loop {
            if k == 0 {
                d.insert(0, b'1');
                d.truncate(p);
                exp10 += 1;
                break;
            }
            k -= 1;
            if d[k] == b'9' {
                d[k] = b'0';
            } else {
                d[k] += 1;
                break;
            }
        }
    }
    (d, exp10)
}

/// Exact decimal expansion of a finite positive double: (digits, exp10) with
/// value = 0.DIGITS * 10^exp10.
fn exact_digits(v: f64) -> (Vec<u8>, i32) {
    // Rust prints the exact value with enough precision ({:.*e} is exact).
    let s = format!("{:.1100e}", v);
    let (m, e) = s.split_once('e').unwrap();
    let e: i32 = e.parse().unwrap();
    let mut digits: Vec<u8> = m.bytes().filter(|c| c.is_ascii_digit()).collect();
    while digits.len() > 1 && *digits.last().unwrap() == b'0' {
        digits.pop();
    }
    (digits, e + 1)
}

/// `printf("%1.<p>g", v)` for finite `v` (glibc semantics, round-half-even on
/// the exact binary value).
pub fn fmt_g(v: f64, p: usize) -> String {
    let p = p.max(1);
    if v == 0.0 {
        return if v.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let neg = v < 0.0;
    let (digits, exp10) = exact_digits(v.abs());
    let (d, e10) = round_digits(&digits, exp10, p);
    // X = exponent in d.ddd form
    let x = e10 - 1;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if x < -4 || x >= p as i32 {
        // scientific
        let mut m = String::new();
        m.push(d[0] as char);
        let frac: String = d[1..].iter().map(|&c| c as char).collect();
        let frac = frac.trim_end_matches('0');
        if !frac.is_empty() {
            m.push('.');
            m.push_str(frac);
        }
        out.push_str(&m);
        out.push('e');
        out.push(if x < 0 { '-' } else { '+' });
        let ax = x.abs();
        if ax < 10 {
            out.push('0');
        }
        out.push_str(&ax.to_string());
    } else {
        // fixed with p - 1 - x decimals
        let s: String = d.iter().map(|&c| c as char).collect();
        let (ip, fp) = if x >= 0 {
            let k = (x + 1) as usize;
            (s[..k].to_string(), s[k..].to_string())
        } else {
            let zeros = "0".repeat((-x - 1) as usize);
            ("0".to_string(), format!("{zeros}{s}"))
        };
        out.push_str(&ip);
        let fp = fp.trim_end_matches('0');
        if !fp.is_empty() {
            out.push('.');
            out.push_str(fp);
        }
    }
    out
}

/// `printf("%f", v)` (6 decimals, round-half-even on the exact value).
pub fn fmt_f6(v: f64) -> String {
    if v.is_nan() {
        return if v.is_sign_negative() { "-nan".into() } else { "nan".into() };
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf".into() } else { "inf".into() };
    }
    // Rust's {:.6} rounds the exact binary value half-to-even like glibc.
    format!("{v:.6}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_format() {
        assert_eq!(fmt_g(2.5, 15), "2.5");
        assert_eq!(fmt_g(0.1, 17), "0.10000000000000001");
        assert_eq!(fmt_g(1e20, 15), "1e+20");
        assert_eq!(fmt_g(1.5e-7, 15), "1.5e-07");
        assert_eq!(fmt_g(0.0001, 15), "0.0001");
        assert_eq!(fmt_g(123456789012.5, 15), "123456789012.5");
        assert_eq!(fmt_g(-3.25, 15), "-3.25");
    }

    #[test]
    fn strtod() {
        assert_eq!(strtod_prefix(b"12.5e3x"), Some((12500.0, 6)));
        assert_eq!(strtod_prefix(b"1.x"), Some((1.0, 2)));
        assert_eq!(strtod_prefix(b"1e"), Some((1.0, 1)));
        assert_eq!(strtod_prefix(b"-"), None);
        assert_eq!(strtod_prefix(b"--1"), None);
        assert_eq!(strtod_prefix(b"1e+5"), Some((1e5, 4)));
    }
}
