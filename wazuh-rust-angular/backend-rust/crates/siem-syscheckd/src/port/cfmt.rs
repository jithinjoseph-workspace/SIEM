//! A small `snprintf` for the C message formats (`%s`, `%d`, `%lu`, `%llu`,
//! `%f`, `%.5f`, `%02x`, `%%`, ...), so log lines keep the C text.

/// One `printf` argument.
#[derive(Clone, Copy)]
pub enum A<'a> {
    S(&'a str),
    B(&'a [u8]),
    I(i64),
    U(u64),
    F(f64),
    C(u8),
}

/// `snprintf(buf, big, fmt, args...)`
pub fn cfmt(fmt: &str, args: &[A]) -> Vec<u8> {
    let f = fmt.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(fmt.len() + 32);
    let mut ai = 0;
    let mut i = 0;
    while i < f.len() {
        if f[i] != b'%' {
            out.push(f[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i < f.len() && f[i] == b'%' {
            out.push(b'%');
            i += 1;
            continue;
        }
        let (mut left, mut zero, mut plus, mut space) = (false, false, false, false);
        while i < f.len() && matches!(f[i], b'-' | b'0' | b'+' | b' ' | b'#') {
            match f[i] {
                b'-' => left = true,
                b'0' => zero = true,
                b'+' => plus = true,
                b' ' => space = true,
                _ => {}
            }
            i += 1;
        }
        let mut width = 0usize;
        while i < f.len() && f[i].is_ascii_digit() {
            width = width * 10 + (f[i] - b'0') as usize;
            i += 1;
        }
        let mut prec: Option<usize> = None;
        if i < f.len() && f[i] == b'.' {
            i += 1;
            let mut p = 0;
            while i < f.len() && f[i].is_ascii_digit() {
                p = p * 10 + (f[i] - b'0') as usize;
                i += 1;
            }
            prec = Some(p);
        }
        while i < f.len() && matches!(f[i], b'h' | b'l' | b'z' | b'j' | b't' | b'L' | b'q') {
            i += 1;
        }
        let Some(&conv) = f.get(i) else { break };
        i += 1;
        let arg = args.get(ai).copied();
        ai += 1;
        let as_i = |a: Option<A>| match a {
            Some(A::I(v)) => v,
            Some(A::U(v)) => v as i64,
            Some(A::F(v)) => v as i64,
            Some(A::C(c)) => c as i64,
            _ => 0,
        };
        let as_u = |a: Option<A>| match a {
            Some(A::I(v)) => v as u64,
            Some(A::U(v)) => v,
            Some(A::F(v)) => v as u64,
            Some(A::C(c)) => c as u64,
            _ => 0,
        };
        let body: Vec<u8> = match conv {
            b'd' | b'i' => {
                let v = as_i(arg);
                let mut s = v.unsigned_abs().to_string();
                if let Some(p) = prec {
                    while s.len() < p {
                        s.insert(0, '0');
                    }
                }
                let sign = if v < 0 { "-" } else if plus { "+" } else if space { " " } else { "" };
                pad_num(sign, &s, width, left, zero && prec.is_none())
            }
            b'u' => pad_num("", &as_u(arg).to_string(), width, left, zero),
            b'x' => pad_num("", &format!("{:x}", as_u(arg)), width, left, zero),
            b'X' => pad_num("", &format!("{:X}", as_u(arg)), width, left, zero),
            b'o' => pad_num("", &format!("{:o}", as_u(arg)), width, left, zero),
            b'c' => pad(vec![as_u(arg) as u8], width, left),
            b's' => {
                let mut b: Vec<u8> = match arg {
                    Some(A::S(s)) => s.as_bytes().to_vec(),
                    Some(A::B(b)) => b.to_vec(),
                    _ => b"(null)".to_vec(),
                };
                if let Some(p) = prec {
                    b.truncate(p);
                }
                pad(b, width, left)
            }
            b'f' | b'F' => {
                let v = match arg {
                    Some(A::F(v)) => v,
                    a => as_i(a) as f64,
                };
                let s = format!("{:.*}", prec.unwrap_or(6), v.abs());
                let sign = if v.is_sign_negative() && v != 0.0 { "-" } else if plus { "+" } else { "" };
                pad_num(sign, &s, width, left, zero)
            }
            b'p' => format!("0x{:x}", as_u(arg)).into_bytes(),
            other => vec![b'%', other],
        };
        out.extend_from_slice(&body);
    }
    out
}

fn pad(b: Vec<u8>, width: usize, left: bool) -> Vec<u8> {
    if b.len() >= width {
        return b;
    }
    let fill = vec![b' '; width - b.len()];
    if left {
        [b, fill].concat()
    } else {
        [fill, b].concat()
    }
}

fn pad_num(sign: &str, digits: &str, width: usize, left: bool, zero: bool) -> Vec<u8> {
    let len = sign.len() + digits.len();
    if len >= width {
        return format!("{sign}{digits}").into_bytes();
    }
    let n = width - len;
    if left {
        format!("{sign}{digits}{}", " ".repeat(n)).into_bytes()
    } else if zero {
        format!("{sign}{}{digits}", "0".repeat(n)).into_bytes()
    } else {
        format!("{}{sign}{digits}", " ".repeat(n)).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(cfmt("(6321): Sending FIM event: %s", &[A::S("x")]), "(6321): Sending FIM event: x".as_bytes());
        assert_eq!(cfmt("%d %lu %02x %%", &[A::I(-3), A::U(7), A::U(10)]), "-3 7 0a %".as_bytes());
        assert_eq!(cfmt("%.5f KB", &[A::F(0.0)]), "0.00000 KB".as_bytes());
        assert_eq!(cfmt("'%s' %d", &[A::S("a")]), "'a' 0".as_bytes());
    }
}
