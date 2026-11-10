//! `shared/yaml2json.c`: libyaml documents to cJSON. libyaml is
//! unsafe-libyaml (libyaml 0.2.5 translated to Rust); the agent ships 0.1.7.
//! shortcut: 0.2.x accepts a few constructs 0.1.7 rejects (':' or '?' inside flow
//! plain scalars, %YAML 1.2); fine for the bundled policies, recheck for odd custom ones.

use std::mem::MaybeUninit;

use siem_cjson::Json;
use unsafe_libyaml as y;

use crate::crt;

/// A loaded `yaml_document_t`.
pub struct Document(Box<y::yaml_document_t>);

impl Drop for Document {
    fn drop(&mut self) {
        // SAFETY: a document yaml_parser_load filled.
        unsafe { y::yaml_document_delete(&mut *self.0) }
    }
}

/// `yaml_parse_file(path, &document)`: the warnings go to `warn`.
pub fn parse_file(path: &str, warn: &mut dyn FnMut(String)) -> Option<Document> {
    // wfopen(path, "rb")
    #[cfg(windows)]
    if siem_fileop::crt::is_network_path(path) {
        warn(siem_fileop::crt::network_path_executed(path));
        warn(format!("Cannot open file '{path}': {} (13)", crt::strerror(13)));
        return None;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            // Windows wfopen: errno = GetLastError()
            let n = e.raw_os_error().unwrap_or(0);
            warn(format!("Cannot open file '{path}': {} ({n})", crt::strerror(n)));
            return None;
        }
    };
    parse_bytes(&data).map_err(|line| warn(format!("Failed to load YAML document in {path}:{line}"))).ok()
}

/// `yaml_parser_load` over `data`: the document, or the problem line.
pub fn parse_bytes(data: &[u8]) -> Result<Document, u64> {
    // SAFETY: the parser reads `data` (alive for the call) and is deleted here; the
    // document is owned by the returned value (loader frees it itself on failure).
    unsafe {
        let mut parser = MaybeUninit::<y::yaml_parser_t>::uninit();
        if y::yaml_parser_initialize(parser.as_mut_ptr()).fail {
            return Err(0);
        }
        let parser = parser.as_mut_ptr();
        y::yaml_parser_set_input_string(parser, data.as_ptr(), data.len() as u64);
        let mut doc: Box<MaybeUninit<y::yaml_document_t>> = Box::new(MaybeUninit::uninit());
        let r = if y::yaml_parser_load(parser, doc.as_mut_ptr()).ok {
            Ok(Document(Box::from_raw(Box::into_raw(doc) as *mut y::yaml_document_t)))
        } else {
            Err((&*parser).problem_mark.line)
        };
        y::yaml_parser_delete(parser);
        r
    }
}

impl Document {
    /// `yaml2json(document, quoted_float_as_string)`
    pub fn to_json(&mut self, quoted_float_as_string: bool, warn: &mut dyn FnMut(String)) -> Option<Json> {
        // SAFETY: nodes of this document.
        unsafe {
            let node = y::yaml_document_get_root_node(&mut *self.0);
            if node.is_null() {
                warn("No document defined.".into());
                return None;
            }
            node_json(&mut self.0, node, quoted_float_as_string, warn)
        }
    }
}

/// A NUL-terminated libyaml string.
unsafe fn c_bytes<'a>(p: *const u8) -> &'a [u8] {
    std::ffi::CStr::from_ptr(p as *const std::ffi::c_char).to_bytes()
}

/// `yaml2json_node`
unsafe fn node_json(doc: &mut y::yaml_document_t, node: *mut y::yaml_node_t, quoted: bool, warn: &mut dyn FnMut(String)) -> Option<Json> {
    match (*node).type_ {
        y::YAML_NO_NODE => Some(Json::object()),
        y::YAML_SCALAR_NODE => {
            let s = (*node).data.scalar;
            let scalar = c_bytes(s.value);
            let (number, used) = crt::strtod(scalar);
            let quoted_style = matches!(s.style, y::YAML_SINGLE_QUOTED_SCALAR_STYLE | y::YAML_DOUBLE_QUOTED_SCALAR_STYLE);
            Some(if quoted && quoted_style || used == 0 || used != scalar.len() { Json::string(scalar) } else { Json::number(number) })
        }
        y::YAML_SEQUENCE_NODE => {
            let mut arr = Json::array();
            let items = (*node).data.sequence.items;
            let mut it = items.start;
            while it < items.top {
                let child = y::yaml_document_get_node(doc, *it);
                if let Some(v) = node_json(doc, child, quoted, warn) {
                    arr.push(v);
                }
                it = it.add(1);
            }
            Some(arr)
        }
        y::YAML_MAPPING_NODE => {
            let mut obj = Json::object();
            let pairs = (*node).data.mapping.pairs;
            let mut p = pairs.start;
            while p < pairs.top {
                let key = y::yaml_document_get_node(doc, (*p).key);
                let value = y::yaml_document_get_node(doc, (*p).value);
                if (*key).type_ != y::YAML_SCALAR_NODE {
                    warn(format!("Mapping key is not scalar (line {}).", (*key).start_mark.line));
                } else if let Some(v) = node_json(doc, value, quoted, warn) {
                    obj.add(c_bytes((*key).data.scalar.value), v);
                }
                p = p.add(1);
            }
            Some(obj)
        }
        _ => {
            warn(format!("Unknown node type (line {}).", (*node).start_mark.line));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(s: &str) -> String {
        let mut d = parse_bytes(s.as_bytes()).ok().unwrap();
        d.to_json(true, &mut |_| {}).unwrap().to_string_unformatted()
    }

    #[test]
    fn scalars() {
        assert_eq!(conv("a: 1\nb: '2'\nc: 1.5x\nd: [x, 3]\n"), r#"{"a":1,"b":"2","c":"1.5x","d":["x",3]}"#);
        assert_eq!(conv("a: 1\na: 2\n"), r#"{"a":1,"a":2}"#);
    }
}
