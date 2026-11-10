//! Port of `src/os_xml/os_xml_writer.c` (`OS_WriteXML`): rewrites the content
//! of the element at path `nodes` in `infile`, writing the result to
//! `outfile`. Used by `manage_agents`/`agent-auth` to edit `ossec.conf`.

use crate::parser::{R_COM, R_CONFE, R_CONFS, XML_MAXSIZE};
use std::path::Path;

/// `XMLW_ERROR` / `XMLW_NOIN` / `XMLW_NOOUT`
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XmlWriteError {
    #[error("XML write error")]
    Error = 0o06,
    #[error("cannot open input file")]
    NoIn = 0o07,
    #[error("cannot open output file")]
    NoOut = 0o10,
}

const EOF: i32 = -1;

struct W<'a> {
    input: &'a [u8],
    pos: usize,
    pushback: Vec<i32>,
    out: Vec<u8>,
}

impl W<'_> {
    fn fgetc(&mut self) -> i32 {
        if let Some(c) = self.pushback.pop() {
            return c;
        }
        if self.pos < self.input.len() {
            self.pos += 1;
            self.input[self.pos - 1] as i32
        } else {
            EOF
        }
    }

    fn ungetc(&mut self, c: i32) {
        if c != EOF {
            self.pushback.push(c);
        }
    }

    /// `_xml_wfgetc`: read and echo.
    fn wfgetc(&mut self) -> i32 {
        let c = self.fgetc();
        if c != EOF {
            self.out.push(c as u8);
        }
        c
    }

    fn putc(&mut self, c: i32) {
        self.out.push(c as u8);
    }

    /// `_oswcomment`
    fn comment(&mut self) -> i32 {
        let mut c = self.fgetc();
        if c == R_COM {
            self.putc(c);
            loop {
                c = self.wfgetc();
                if c == EOF {
                    break;
                }
                if c == R_COM {
                    c = self.fgetc();
                    if c == R_CONFE {
                        self.putc(c);
                        return 1;
                    }
                    self.ungetc(c);
                } else if c == b'-' as i32 {
                    c = self.fgetc();
                    if c == b'-' as i32 {
                        self.putc(c);
                        c = self.fgetc();
                        if c == R_CONFE {
                            self.putc(c);
                            return 1;
                        }
                        self.ungetc(c);
                    } else {
                        self.ungetc(c);
                    }
                }
            }
            return -1;
        } else {
            self.ungetc(c);
        }
        0
    }

    /// `_WReadElem`
    fn read_elem(&mut self, position: u32, parent: u32, nodes: &[&str], val: &str, mut node_pos: u32) -> i32 {
        let mut ret_code = 0;
        let mut count = 0usize;
        let mut location = -1;
        let mut elem: Vec<u8> = Vec::new();
        let mut closedelim: Vec<u8> = Vec::new();

        loop {
            let mut c = self.wfgetc();
            if c == EOF {
                break;
            }
            if count >= XML_MAXSIZE {
                return -1;
            }
            if c == R_CONFS {
                let r = self.comment();
                if r < 0 {
                    return -1;
                } else if r == 1 {
                    continue;
                }
            }

            if location == -1 {
                if c == R_CONFS {
                    c = self.fgetc();
                    if c == b'/' as i32 {
                        return -1;
                    } else {
                        self.ungetc(c);
                    }
                    location = 0;
                } else {
                    continue;
                }
            } else if location == 0 && (c == R_CONFE || c == b' ' as i32) {
                let mut ge = false;
                elem.truncate(count);
                if count > 0 && elem[count - 1] == b'/' {
                    ge = true;
                    elem.truncate(count - 1);
                }
                if c == b' ' as i32 {
                    loop {
                        c = self.wfgetc();
                        if c == EOF || c == R_CONFE {
                            break;
                        }
                    }
                }
                if ge {
                    count = 0;
                    location = -1;
                    elem.clear();
                    closedelim.clear();
                    if parent > 0 {
                        return ret_code;
                    }
                } else {
                    count = 0;
                    location = 1;
                }
                if node_pos > position {
                    node_pos = 0;
                }
                let np = node_pos as usize;
                if node_pos == position && np < nodes.len() && elem == nodes[np].as_bytes() {
                    node_pos += 1;
                    if node_pos as usize >= nodes.len() {
                        ret_code = 1;
                        self.out.extend_from_slice(val.as_bytes());
                        loop {
                            c = self.fgetc();
                            if c == EOF {
                                break;
                            }
                            if c == R_CONFS {
                                self.ungetc(c);
                                break;
                            }
                        }
                    }
                }
            } else if location == 2 && c == R_CONFE {
                closedelim.truncate(count);
                if closedelim != elem {
                    return -1;
                }
                elem.clear();
                closedelim.clear();
                count = 0;
                location = -1;
                if parent > 0 {
                    return ret_code;
                }
            } else if location == 1 && c == R_CONFS {
                c = self.fgetc();
                if c == b'/' as i32 {
                    self.putc(c);
                    count = 0;
                    location = 2;
                } else {
                    self.ungetc(c);
                    self.ungetc(R_CONFS);
                    // fseek(fp_out, -1, SEEK_CUR): drop the '<' already echoed
                    if self.out.pop().is_none() {
                        return -1;
                    }
                    let w = self.read_elem(position + 1, parent + 1, nodes, val, node_pos);
                    if w < 0 {
                        return -1;
                    }
                    if w == 1 {
                        ret_code = 1;
                    }
                    count = 0;
                }
            } else {
                if location == 0 {
                    elem.truncate(count);
                    elem.push(c as u8);
                    count += 1;
                } else if location == 1 {
                    count += 1;
                } else if location == 2 {
                    closedelim.truncate(count);
                    closedelim.push(c as u8);
                    count += 1;
                }
            }
        }
        if location == -1 {
            return ret_code;
        }
        -1
    }
}

/// C `printf("%*c", width, ' ')`.
fn pad(width: i32) -> String {
    let w = width.unsigned_abs() as usize;
    " ".repeat(w.max(1))
}

/// `OS_WriteXML`
pub fn write_xml(
    infile: impl AsRef<Path>,
    outfile: impl AsRef<Path>,
    nodes: &[&str],
    oldval: Option<&str>,
    newval: &str,
) -> Result<(), XmlWriteError> {
    let input = std::fs::read(infile).map_err(|_| XmlWriteError::NoIn)?;
    let mut w = W { input: &input, pos: 0, pushback: Vec::new(), out: Vec::new() };
    let r = w.read_elem(0, 0, nodes, newval, 0);
    if r < 0 {
        let _ = std::fs::write(outfile.as_ref(), &w.out);
        return Err(XmlWriteError::Error);
    }
    if oldval.is_none() && r == 0 && !nodes.is_empty() {
        let mut s = String::from("\n");
        let mut rwidth: i32 = 0;
        for (k, n) in nodes.iter().enumerate() {
            s.push_str(&pad(rwidth));
            s.push('<');
            s.push_str(n);
            s.push('>');
            rwidth += 3;
            if k + 1 < nodes.len() {
                s.push('\n');
            }
        }
        rwidth -= 6;
        let last = nodes.len() - 1;
        s.push_str(newval);
        s.push_str(&format!("</{}>\n", nodes[last]));
        for k in (0..last).rev() {
            s.push_str(&pad(rwidth));
            s.push_str(&format!("</{}>\n", nodes[k]));
            rwidth -= 3;
        }
        w.out.extend_from_slice(s.as_bytes());
    }
    std::fs::write(outfile.as_ref(), &w.out).map_err(|_| XmlWriteError::NoOut)
}
