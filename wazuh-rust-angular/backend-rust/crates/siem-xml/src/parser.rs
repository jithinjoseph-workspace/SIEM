//! Port of `src/os_xml/os_xml.c` (`OS_ReadXML`, `OS_ReadXMLString`,
//! `ParseXML`, `_ReadElem`, `_getattributes`, `_oscomment`).
//!
//! Wazuh XML is not standard XML: a document may have several root elements,
//! entities such as `&lt;` are **not** decoded, `\<` escapes a `<` inside
//! content, and `<!-- ... -->` / `<! ... !>` comments are allowed anywhere.
//! Rules, decoders, `ossec.conf` and `agent.conf` all rely on that, so this
//! module mirrors the C state machine byte for byte.

use crate::{OsXml, XmlType};

pub(crate) const R_CONFS: i32 = b'<' as i32;
pub(crate) const R_CONFE: i32 = b'>' as i32;
pub(crate) const R_COM: i32 = b'!' as i32;
const LEOF: i32 = -2;
pub(crate) const XML_MAXSIZE: usize = 20480;
const XML_MAX_ATTR_DEPTH: u32 = 48;
pub(crate) const XML_ERR_LENGTH: usize = 128;
const XML_STASH_LEN: usize = 2;
const EOF: i32 = -1;

/// C-locale `isspace`.
#[inline]
pub(crate) fn c_isspace(c: i32) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d)
}

/// Character source: a file (EOF = -1, NUL bytes are ordinary characters)
/// or a C string (stops at the first NUL, which is returned as 0).
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    is_file: bool,
    stash: [i32; XML_STASH_LEN],
    stash_i: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8], is_file: bool) -> Self {
        Self { data, pos: 0, is_file, stash: [0; XML_STASH_LEN], stash_i: 0 }
    }

    fn end_marker(&self) -> i32 {
        if self.is_file {
            EOF
        } else {
            0
        }
    }
}

struct Parser<'a, 'x> {
    r: Reader<'a>,
    x: &'x mut OsXml,
}

impl<'a, 'x> Parser<'a, 'x> {
    /// `_xml_fgetc` / `_xml_sgetc`
    fn getc(&mut self) -> i32 {
        let c = if self.r.stash_i > 0 {
            self.r.stash_i -= 1;
            self.r.stash[self.r.stash_i]
        } else if self.r.pos < self.r.data.len() {
            let b = self.r.data[self.r.pos];
            if !self.r.is_file && b == 0 {
                // A C string ends at the first NUL; keep returning 0.
                0
            } else {
                self.r.pos += 1;
                b as i32
            }
        } else {
            self.r.end_marker()
        };
        if c == b'\n' as i32 {
            self.x.line += 1;
        }
        c
    }

    /// `_xml_ungetc`
    fn ungetc(&mut self, c: i32) {
        if self.r.stash_i >= XML_STASH_LEN {
            return;
        }
        self.r.stash[self.r.stash_i] = c;
        self.r.stash_i += 1;
        if c == b'\n' as i32 {
            self.x.line -= 1;
        }
    }

    fn error(&mut self, msg: String) {
        self.x.set_error(msg);
    }

    /// `_oscomment`: 1 = comment consumed, 0 = not a comment, -1 = unterminated.
    fn oscomment(&mut self, delim: i32) -> i32 {
        let mut c = self.getc();
        if c == R_COM {
            loop {
                c = self.getc();
                if c == delim {
                    break;
                }
                if c == R_COM {
                    c = self.getc();
                    if c == R_CONFE {
                        return 1;
                    }
                    self.ungetc(c);
                } else if c == b'-' as i32 {
                    c = self.getc();
                    if c == b'-' as i32 {
                        c = self.getc();
                        if c == R_CONFE {
                            return 1;
                        }
                        self.ungetc(c);
                    }
                    self.ungetc(c);
                }
            }
            return -1;
        } else {
            self.ungetc(c);
        }
        0
    }

    /// `_ReadElem`
    fn read_elem(&mut self, parent: u32, mut recursion_level: u32, truncate: bool) -> i32 {
        recursion_level += 1;
        if recursion_level > 1024 {
            self.error("XMLERR: Max recursion level reached".into());
            return -1;
        }

        let mut count: usize = 0;
        let mut currently_cont: usize = 0;
        let mut location: i32 = -1;
        let mut retval = -1;
        let mut ignore_content = false;
        let mut prevv: i32 = 1;
        // C buffers of XML_MAXSIZE + 1 bytes, overwritten in place by `count`.
        let mut elem = vec![0u8; XML_MAXSIZE + 1];
        let mut cont = vec![0u8; XML_MAXSIZE + 1];
        let mut closedelim = vec![0u8; XML_MAXSIZE + 1];
        let cmp = self.r.end_marker();

        let cstr = |b: &[u8]| -> Vec<u8> {
            let n = b.iter().position(|&x| x == 0).unwrap_or(b.len());
            b[..n].to_vec()
        };

        loop {
            let mut c = self.getc();
            if c == cmp {
                break;
            }
            if c == b'\\' as i32 {
                prevv *= -1;
            } else if c != R_CONFS && prevv == -1 {
                prevv = 1;
            }

            if count >= XML_MAXSIZE {
                if truncate && location == 1 {
                    ignore_content = true;
                } else {
                    self.error("XMLERR: String overflow.".into());
                    return retval;
                }
            }

            if c == R_CONFS {
                let r = self.oscomment(cmp);
                if r < 0 {
                    self.error("XMLERR: Comment not closed.".into());
                    return retval;
                } else if r == 1 {
                    continue;
                }
            }

            if location == -1 && prevv == 1 {
                if c == R_CONFS {
                    c = self.getc();
                    if c == b'/' as i32 {
                        self.error("XMLERR: Element not opened.".into());
                        return retval;
                    } else {
                        self.ungetc(c);
                    }
                    location = 0;
                } else {
                    continue;
                }
            } else if location == 0 && (c == R_CONFE || c_isspace(c)) {
                let mut ge = 0;
                let mut ga = 0;
                elem[count] = 0;
                if count > 0 && elem[count - 1] == b'/' {
                    ge = b'/' as i32;
                    elem[count - 1] = 0;
                }
                let name = cstr(&elem);
                self.x.writememory(name, XmlType::Elem, parent);
                currently_cont = self.x.cur() - 1;
                if c_isspace(c) {
                    ga = self.getattributes(parent, truncate, cmp, 0);
                    if ga < 0 {
                        return retval;
                    }
                }

                if ge == b'/' as i32 || ga == b'/' as i32 {
                    self.x.ct[currently_cont] = Some(Vec::new());
                    self.x.ck[currently_cont] = true;
                    currently_cont = 0;
                    count = 0;
                    location = -1;
                    elem[..XML_MAXSIZE].fill(0);
                    closedelim[..XML_MAXSIZE].fill(0);
                    cont[..XML_MAXSIZE].fill(0);
                    if parent > 0 {
                        return 0;
                    }
                } else {
                    count = 0;
                    location = 1;
                }
            } else if location == 2 && c == R_CONFE {
                closedelim[count] = 0;
                if cstr(&closedelim) != cstr(&elem) {
                    let e = String::from_utf8_lossy(&cstr(&elem)).into_owned();
                    self.error(format!("XMLERR: Element '{e}' not closed."));
                    return retval;
                }
                self.x.ct[currently_cont] = Some(cstr(&cont));
                self.x.ck[currently_cont] = true;
                elem[..XML_MAXSIZE].fill(0);
                closedelim[..XML_MAXSIZE].fill(0);
                cont[..XML_MAXSIZE].fill(0);
                currently_cont = 0;
                count = 0;
                location = -1;
                if parent > 0 {
                    return 0;
                }
            } else if location == 1 && c == R_CONFS && prevv == 1 {
                c = self.getc();
                if c == b'/' as i32 {
                    cont[count] = 0;
                    count = 0;
                    location = 2;
                    ignore_content = false;
                } else {
                    self.ungetc(c);
                    self.ungetc(R_CONFS);
                    if self.read_elem(parent + 1, recursion_level, truncate) < 0 {
                        return retval;
                    }
                    count = 0;
                }
            } else {
                // The C code stores `(char) c`; EOF/negative values never get here
                // except as (char)-1 on the string path, which we never produce.
                let byte = c as u8;
                if location == 0 {
                    elem[count] = byte;
                    count += 1;
                } else if location == 1 && !ignore_content {
                    cont[count] = byte;
                    count += 1;
                } else if location == 2 {
                    closedelim[count] = byte;
                    count += 1;
                }
                if c == R_CONFS {
                    prevv = 1;
                }
            }
        }

        if location == -1 {
            retval = LEOF;
        }
        self.error("XMLERR: End of file and some elements were not closed.".into());
        retval
    }

    /// `_getattributes`
    fn getattributes(&mut self, parent: u32, truncate: bool, delim: i32, depth: u32) -> i32 {
        if depth > XML_MAX_ATTR_DEPTH {
            self.error("XMLERR: Too many attributes.".into());
            return -1;
        }
        let mut location = 0;
        let mut count: usize = 0;
        let mut c_to_match: i32 = 0;
        let mut attr: Vec<u8> = Vec::new();
        let mut value: Vec<u8> = Vec::new();

        loop {
            let mut c = self.getc();
            if c == delim {
                break;
            }
            if count >= XML_MAXSIZE {
                if truncate && location == 1 {
                    return 0;
                }
                attr.truncate(count.saturating_sub(1));
                let a: String = String::from_utf8_lossy(&attr).chars().take(20).collect();
                self.error(format!("XMLERR: Overflow attempt at attribute '{a}'."));
                return -1;
            } else if c == R_CONFE || (location == 0 && c == b'/' as i32) {
                if location == 1 {
                    let a = String::from_utf8_lossy(&attr).into_owned();
                    self.error(format!("XMLERR: Attribute '{a}' not closed."));
                    return -1;
                } else if location == 0 && count > 0 {
                    let a = String::from_utf8_lossy(&attr).into_owned();
                    self.error(format!("XMLERR: Attribute '{a}' has no value."));
                    return -1;
                } else if c == b'/' as i32 {
                    return c;
                } else {
                    return 0;
                }
            } else if location == 0 && c == b'=' as i32 {
                // Check for an existing attribute with the same name
                let cur = self.x.cur();
                if cur > 0 {
                    let mut i = cur - 1;
                    while self.x.rl[i] == parent && self.x.tp[i] == XmlType::Attr {
                        if self.x.el[i] == attr {
                            let a = String::from_utf8_lossy(&attr).into_owned();
                            self.error(format!("XMLERR: Attribute '{a}' already defined."));
                            return -1;
                        }
                        if i == 0 {
                            break;
                        }
                        i -= 1;
                    }
                }

                c = self.getc();
                if c != b'"' as i32 && c != b'\'' as i32 {
                    let mut err = true;
                    if c_isspace(c) {
                        loop {
                            c = self.getc();
                            if c == delim {
                                break;
                            }
                            if c_isspace(c) {
                                continue;
                            } else if c == b'"' as i32 || c == b'\'' as i32 {
                                err = false;
                                break;
                            } else {
                                break;
                            }
                        }
                    }
                    if err {
                        let a = String::from_utf8_lossy(&attr).into_owned();
                        self.error(format!("XMLERR: Attribute '{a}' not followed by a \" or '."));
                        return -1;
                    }
                }
                c_to_match = c;
                location = 1;
                count = 0;
            } else if location == 0 && c_isspace(c) {
                if count == 0 {
                    continue;
                } else {
                    let a = String::from_utf8_lossy(&attr).into_owned();
                    self.error(format!("XMLERR: Attribute '{a}' has no value."));
                    return -1;
                }
            } else if location == 1 && c == c_to_match {
                self.x.writememory(attr.clone(), XmlType::Attr, parent);
                let idx = self.x.cur() - 1;
                self.x.ct[idx] = Some(value[..count].to_vec());
                c = self.getc();
                if c_isspace(c) {
                    return self.getattributes(parent, truncate, delim, depth + 1);
                } else if c == R_CONFE {
                    return 0;
                } else if c == b'/' as i32 {
                    return c;
                }
                let a = String::from_utf8_lossy(&attr).into_owned();
                let v = String::from_utf8_lossy(&value[..count]).into_owned();
                self.error(format!("XMLERR: Bad attribute closing for '{a}'='{v}'."));
                return -1;
            } else if location == 0 {
                attr.truncate(count);
                attr.push(c as u8);
                count += 1;
            } else if location == 1 {
                value.truncate(count);
                value.push(c as u8);
                count += 1;
            }
        }

        self.error("XMLERR: End of file while reading an attribute.".into());
        -1
    }
}

/// `ParseXML`: returns 0 on success, -1 on error (message in `x.err`).
pub(crate) fn parse_xml(x: &mut OsXml, data: &[u8], is_file: bool, truncate: bool) -> i32 {
    x.line = 1;
    let mut p = Parser { r: Reader::new(data, is_file), x };
    let r = p.read_elem(0, 0, truncate);
    if r < 0 && r != LEOF {
        return -1;
    }
    for i in 0..x.cur() {
        if !x.ck[i] {
            let e = String::from_utf8_lossy(&x.el[i]).into_owned();
            x.set_error(format!("XMLERR: Element '{e}' not closed."));
            return -1;
        }
    }
    0
}
