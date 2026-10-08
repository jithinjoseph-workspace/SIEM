//! Port of `src/os_xml/os_xml_variables.c` (`OS_ApplyVariables`): replaces
//! `$NAME` references in element and attribute contents with the value of
//! `<var name="NAME">value</var>` definitions that appear earlier in the file.

use crate::{OsXml, XmlType};

const XML_VARIABLE_MAXSIZE: usize = 256;
const XML_VAR_ATTRIBUTE: &[u8] = b"name";

fn is_var_end(c: u8) -> bool {
    matches!(c, b'$' | 0 | b'.' | b'|' | b',' | b' ')
}

fn cstrlen(b: &[u8]) -> usize {
    b.iter().position(|&x| x == 0).unwrap_or(b.len())
}

impl OsXml {
    fn var_fail(&mut self, msg: String, line: u32) -> Result<(), crate::XmlError> {
        self.set_error(msg);
        self.err_line = line;
        Err(crate::XmlError { message: self.last_error().to_string(), line, code: -1 })
    }

    /// `OS_ApplyVariables`
    pub fn apply_variables(&mut self) -> Result<(), crate::XmlError> {
        let mut vars: Vec<Vec<u8>> = Vec::new();
        let mut values: Vec<Vec<u8>> = Vec::new();

        let cur = self.cur();
        for i in 0..cur {
            if self.tp[i] == XmlType::Variable {
                let mut found = false;
                for j in i + 1..cur {
                    if self.rl[j] < self.rl[i] {
                        break;
                    } else if self.tp[j] == XmlType::Attr {
                        if self.el[j].eq_ignore_ascii_case(XML_VAR_ATTRIBUTE) {
                            match &self.ct[j] {
                                None => {
                                    let l = self.ln[j];
                                    return self.var_fail("XMLERR: Invalid variable content.".into(), l);
                                }
                                Some(c) if cstrlen(c) >= XML_VARIABLE_MAXSIZE => {
                                    let l = self.ln[j];
                                    return self.var_fail("XMLERR: Invalid variable name size.".into(), l);
                                }
                                Some(c) => {
                                    vars.push(c[..cstrlen(c)].to_vec());
                                    found = true;
                                    break;
                                }
                            }
                        } else {
                            let l = self.ln[j];
                            return self.var_fail(
                                "XMLERR: Only \"name\" is allowed as an attribute for a variable.".into(),
                                l,
                            );
                        }
                    }
                }
                if !found || self.ct[i].is_none() {
                    // A name found without content still counts as pushed in C,
                    // but the function fails immediately anyway.
                    let l = self.ln[i];
                    return self.var_fail("XMLERR: No value set for variable.".into(), l);
                }
                let v = self.ct[i].clone().unwrap();
                values.push(v[..cstrlen(&v)].to_vec());
            } else if (self.tp[i] == XmlType::Elem || self.tp[i] == XmlType::Attr) && self.ct[i].is_some() {
                let s = vars.len();
                let ct_len = cstrlen(self.ct[i].as_ref().unwrap());
                if ct_len <= 2 || s == 0 {
                    continue;
                }
                // p walks a copy of the original content.
                let orig = self.ct[i].as_ref().unwrap()[..ct_len].to_vec();
                let pc = |k: usize| orig.get(k).copied().unwrap_or(0);
                let mut ct: Vec<u8> = orig.clone();
                let mut p = 0usize;
                let mut init = 0usize;

                while pc(p) != 0 {
                    if pc(p) == b'$' {
                        let mut lvar: Vec<u8> = Vec::new();
                        p += 1;
                        loop {
                            if is_var_end(pc(p)) {
                                let mut j = 0usize;
                                while j < s {
                                    if !vars[j].eq_ignore_ascii_case(&lvar) {
                                        j += 1;
                                        continue;
                                    }
                                    // ct = ct[..init] + value + p..
                                    let mut n = ct[..init.min(ct.len())].to_vec();
                                    n.extend_from_slice(&values[j]);
                                    init = n.len();
                                    n.extend_from_slice(&orig[p..]);
                                    ct = n;
                                    break;
                                }
                                if lvar.first() == Some(&b'(') {
                                    break;
                                }
                                if j == s && !lvar.is_empty() {
                                    self.ct[i] = Some(ct);
                                    let l = self.ln[i];
                                    let shown: String = String::from_utf8_lossy(&lvar).chars().take(95).collect();
                                    return self.var_fail(format!("XMLERR: Unknown variable: '{shown}'."), l);
                                } else if j == s {
                                    init += 1;
                                }
                                break;
                            }
                            if lvar.len() >= XML_VARIABLE_MAXSIZE - 1 {
                                self.ct[i] = Some(ct);
                                let l = self.ln[i];
                                let tp = lvar.len();
                                return self.var_fail(format!("XMLERR: Invalid variable name size: '{tp}'."), l);
                            }
                            lvar.push(pc(p));
                            p += 1;
                        }
                        // go_next: the terminator is examined on the next pass.
                        continue;
                    }
                    p += 1;
                    init += 1;
                }
                self.ct[i] = Some(ct);
            }
        }
        Ok(())
    }
}
