//! `siem-xml`: faithful port of Wazuh's XML library `src/os_xml/`.
//!
//! Every Wazuh configuration file is read through this parser: `ossec.conf`,
//! `agent.conf`, `local_internal_options`, rules, decoders, and lists. It
//! keeps the C library's flat-array document model (`el`, `ct`, `tp`, `rl`,
//! `ck`, `ln`), so all the `OS_Get*` lookups behave exactly as they do in Wazuh.

mod access;
pub mod dump;
mod parser;
mod variables;
mod writer;

pub use access::RawNode;
pub use writer::{write_xml, XmlWriteError};

use std::path::Path;

/// `XML_TYPE`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlType {
    Attr,
    Elem,
    /// `XML_VARIABLE_BEGIN` — an element (or attribute) named `var`.
    Variable,
}

/// `xml_node`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XmlNode {
    /// Index of the element in the document arrays (`key`).
    pub key: usize,
    pub element: String,
    pub content: Option<String>,
    pub attributes: Vec<String>,
    pub values: Vec<String>,
}

impl XmlNode {
    /// `w_get_attr_val_by_name`
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.iter().position(|a| a == name).map(|i| self.values[i].as_str())
    }

    /// Content as `&str` ("" when absent).
    pub fn text(&self) -> &str {
        self.content.as_deref().unwrap_or("")
    }
}

/// Parse error: message (as Wazuh prints it), line, and the C return code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} (line {line})")]
pub struct XmlError {
    pub message: String,
    pub line: u32,
    /// -1 for parse errors, -2 when the file cannot be opened.
    pub code: i32,
}

/// `OS_XML`
#[derive(Debug, Clone, Default)]
pub struct OsXml {
    pub(crate) el: Vec<Vec<u8>>,
    pub(crate) ct: Vec<Option<Vec<u8>>>,
    pub(crate) tp: Vec<XmlType>,
    pub(crate) rl: Vec<u32>,
    pub(crate) ck: Vec<bool>,
    pub(crate) ln: Vec<u32>,
    pub(crate) fol: i64,
    pub(crate) line: u32,
    err: String,
    err_line: u32,
}

impl OsXml {
    pub(crate) fn cur(&self) -> usize {
        self.el.len()
    }

    pub(crate) fn set_error(&mut self, msg: String) {
        // vsnprintf(err, XML_ERR_LENGTH - 1, ...)
        let mut m = msg.into_bytes();
        m.truncate(parser::XML_ERR_LENGTH - 2);
        self.err = String::from_utf8_lossy(&m).into_owned();
        self.err_line = self.line;
    }

    /// `_writememory`
    pub(crate) fn writememory(&mut self, name: Vec<u8>, ty: XmlType, parent: u32) {
        let is_var = name.eq_ignore_ascii_case(b"var");
        self.el.push(name);
        self.ct.push(None);
        self.tp.push(if is_var { XmlType::Variable } else { ty });
        self.rl.push(parent);
        self.ck.push(ty == XmlType::Attr);
        self.ln.push(self.line);
    }

    fn from_bytes(data: &[u8], is_file: bool, truncate: bool) -> Result<Self, XmlError> {
        let mut x = OsXml::default();
        if parser::parse_xml(&mut x, data, is_file, truncate) < 0 {
            return Err(XmlError { message: x.err.clone(), line: x.err_line, code: -1 });
        }
        Ok(x)
    }

    /// `OS_ReadXML` / `OS_ReadXML_Ex`.
    pub fn read_file(path: impl AsRef<Path>, truncate: bool) -> Result<Self, XmlError> {
        let path = path.as_ref();
        match std::fs::read(path) {
            Ok(data) => Self::from_bytes(&data, true, truncate),
            Err(_) => {
                let mut x = OsXml::default();
                x.set_error(format!("XMLERR: File '{}' not found.", path.display()));
                Err(XmlError { message: x.err, line: 0, code: -2 })
            }
        }
    }

    /// `OS_ReadXMLString` / `OS_ReadXMLString_Ex` (stops at the first NUL).
    pub fn read_string(s: &str, truncate: bool) -> Result<Self, XmlError> {
        Self::from_bytes(s.as_bytes(), false, truncate)
    }

    /// `OS_ReadXMLString` on raw bytes (stops at the first NUL).
    pub fn read_string_bytes(data: &[u8], truncate: bool) -> Result<Self, XmlError> {
        Self::from_bytes(data, false, truncate)
    }

    /// Parse raw bytes the way a file is parsed.
    pub fn read_bytes(data: &[u8], truncate: bool) -> Result<Self, XmlError> {
        Self::from_bytes(data, true, truncate)
    }

    /// The last error message (`err`), also set after successful parses.
    pub fn last_error(&self) -> &str {
        &self.err
    }

    /// Line recorded with the last error message.
    pub fn last_error_line(&self) -> u32 {
        self.err_line
    }

    pub fn len(&self) -> usize {
        self.cur()
    }

    pub fn is_empty(&self) -> bool {
        self.el.is_empty()
    }

    /// Raw access for diagnostics/tests: (type, relation, name, content, line).
    pub fn entry(&self, i: usize) -> (XmlType, u32, String, Option<String>, u32) {
        (
            self.tp[i],
            self.rl[i],
            String::from_utf8_lossy(&self.el[i]).into_owned(),
            self.ct[i].as_ref().map(|c| String::from_utf8_lossy(c).into_owned()),
            self.ln[i],
        )
    }
}
