//! Canonical text dump of a parse, identical to `tools/xml_harness.c`, used by
//! the differential tests against the C `os_xml`.

use crate::{OsXml, XmlNode, XmlType};
use std::fmt::Write;

fn hex(out: &mut String, s: Option<&[u8]>) {
    match s {
        None => out.push('~'),
        Some(b) => {
            let n = b.iter().position(|&x| x == 0).unwrap_or(b.len());
            if n == 0 {
                out.push('-');
            } else {
                for x in &b[..n] {
                    let _ = write!(out, "{x:02x}");
                }
            }
        }
    }
}

fn tp_code(t: XmlType) -> i32 {
    match t {
        XmlType::Attr => 0,
        XmlType::Elem => 1,
        XmlType::Variable => b'$' as i32,
    }
}

fn dump_arrays(x: &OsXml, out: &mut String) {
    for i in 0..x.cur() {
        let _ = write!(out, "E {i} {} {} {} {} ", tp_code(x.tp[i]), x.rl[i], x.ck[i] as i32, x.ln[i]);
        hex(out, Some(&x.el[i]));
        out.push(' ');
        hex(out, x.ct[i].as_deref());
        out.push('\n');
    }
}

fn dump_nodes(x: &OsXml, parent: Option<&XmlNode>, depth: usize, out: &mut String) {
    let Some(nodes) = x.get_elements_by_node(parent) else { return };
    for n in &nodes {
        let _ = write!(out, "N {depth} {} ", n.key);
        hex(out, Some(n.element.as_bytes()));
        out.push(' ');
        hex(out, n.content.as_deref().map(str::as_bytes));
        for (a, v) in n.attributes.iter().zip(&n.values) {
            out.push(' ');
            hex(out, Some(a.as_bytes()));
            out.push('=');
            hex(out, Some(v.as_bytes()));
        }
        out.push('\n');
        if depth < 12 {
            dump_nodes(x, Some(n), depth + 1, out);
        }
    }
}

/// Dump the result of a parse exactly like the C harness.
pub fn dump(result: Result<OsXml, crate::XmlError>) -> String {
    let mut out = String::new();
    match result {
        Err(e) => {
            let _ = write!(out, "R {} {} ", e.code, e.line);
            hex(&mut out, Some(e.message.as_bytes()));
            out.push('\n');
        }
        Ok(mut x) => {
            let _ = write!(out, "R 0 {} ", x.last_error_line());
            hex(&mut out, Some(x.last_error().as_bytes()));
            out.push('\n');
            dump_arrays(&x, &mut out);
            match x.apply_variables() {
                Ok(()) => {
                    out.push_str("V 0 0 -\n");
                    dump_arrays(&x, &mut out);
                }
                Err(e) => {
                    let _ = write!(out, "V -1 {} ", e.line);
                    hex(&mut out, Some(e.message.as_bytes()));
                    out.push('\n');
                }
            }
            dump_nodes(&x, None, 0, &mut out);
            out.push('G');
            if let Some(roots) = x.get_elements(None) {
                for r in roots {
                    out.push(' ');
                    hex(&mut out, Some(r.as_bytes()));
                }
            }
            out.push('\n');
        }
    }
    out.push_str("END\n");
    out
}
