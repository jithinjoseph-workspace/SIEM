//! Wazuh XML Parser and Engine (src/os_xml)
//!
//! Full 1-to-1 port of Wazuh's custom XML parser:
//! - `os_xml.c`, `os_xml.h`: XML DOM tokenizer, node representations, and parser.
//! - `os_xml_variables.c`: `<var name="...">...</var>` variable extraction and `$VAR` substitution.
//! - `os_xml_access.c`, `os_xml_node_access.c`: Hierarchical XPath-like element querying (`OS_GetElements`, `OS_GetElementContent`, `OS_ElementExist`).
//! - `os_xml_writer.c`: XML DOM formatting, serialization, and atomic file saving.

use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

/// An XML DOM Node representing an element, its attributes, inner content, and children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlNode {
    pub name: String,
    pub content: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            content: String::new(),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    /// Retrieve an attribute value by attribute name.
    pub fn get_attribute(&self, attr: &str) -> Option<&str> {
        self.attributes.get(attr).map(|s| s.as_str())
    }

    /// Find first child element matching name.
    pub fn get_child(&self, child_name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.name == child_name)
    }

    /// Find all direct children matching name.
    pub fn get_children(&self, child_name: &str) -> Vec<&XmlNode> {
        self.children
            .iter()
            .filter(|c| c.name == child_name)
            .collect()
    }
}

/// The Wazuh XML document representation (OS_XML).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsXml {
    pub root_nodes: Vec<XmlNode>,
    pub variables: HashMap<String, String>,
}

impl OsXml {
    pub fn new() -> Self {
        Self {
            root_nodes: Vec::new(),
            variables: HashMap::new(),
        }
    }

    /// Parse an XML string into an `OsXml` DOM tree.
    pub fn parse_str(xml: &str) -> Result<Self, String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut node_stack: Vec<XmlNode> = Vec::new();
        let mut roots: Vec<XmlNode> = Vec::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let mut node = XmlNode::new(&tag_name);

                    for attr in e.attributes() {
                        let attr = attr.map_err(|err| format!("Attribute parse error: {}", err))?;
                        let k = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let v = attr
                            .decode_and_unescape_value(reader.decoder())
                            .map_err(|err| format!("Attribute value unescape error: {}", err))?
                            .to_string();
                        node.attributes.insert(k, v);
                    }

                    node_stack.push(node);
                }
                Ok(Event::Empty(e)) => {
                    let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let mut node = XmlNode::new(&tag_name);

                    for attr in e.attributes() {
                        let attr = attr.map_err(|err| format!("Attribute parse error: {}", err))?;
                        let k = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let v = attr
                            .decode_and_unescape_value(reader.decoder())
                            .map_err(|err| format!("Attribute value unescape error: {}", err))?
                            .to_string();
                        node.attributes.insert(k, v);
                    }

                    if let Some(parent) = node_stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        roots.push(node);
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = e
                        .unescape()
                        .map_err(|err| format!("Text unescape error: {}", err))?
                        .trim()
                        .to_string();
                    if !text.is_empty() {
                        if let Some(current) = node_stack.last_mut() {
                            if !current.content.is_empty() {
                                current.content.push(' ');
                            }
                            current.content.push_str(&text);
                        }
                    }
                }
                Ok(Event::CData(e)) => {
                    let text = String::from_utf8_lossy(e.as_ref()).to_string();
                    if let Some(current) = node_stack.last_mut() {
                        current.content.push_str(&text);
                    }
                }
                Ok(Event::End(_)) => {
                    if let Some(finished_node) = node_stack.pop() {
                        if let Some(parent) = node_stack.last_mut() {
                            parent.children.push(finished_node);
                        } else {
                            roots.push(finished_node);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(err) => return Err(format!("XML syntax error: {}", err)),
                _ => {}
            }
            buf.clear();
        }

        let mut os_xml = Self {
            root_nodes: roots,
            variables: HashMap::new(),
        };

        // Automatically extract and apply <var name="...">...</var> variables
        os_xml.apply_variables();

        Ok(os_xml)
    }

    /// Parse an XML file from disk.
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut file =
            File::open(&path).map_err(|e| format!("Failed to open XML file: {}", e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| format!("Failed to read XML file: {}", e))?;
        Self::parse_str(&content)
    }

    /// Port of `os_xml_variables.c: OS_ApplyVariables`:
    /// Extracts all `<var name="NAME">value</var>` tags and substitutes `$NAME` throughout
    /// all element text contents and attribute values.
    pub fn apply_variables(&mut self) {
        // 1. Collect all variables
        let mut vars = HashMap::new();
        Self::collect_vars_recursive(&self.root_nodes, &mut vars);
        self.variables = vars;

        // 2. If variables exist, substitute across all nodes
        if !self.variables.is_empty() {
            for root in &mut self.root_nodes {
                Self::substitute_vars_recursive(root, &self.variables);
            }
        }
    }

    fn collect_vars_recursive(nodes: &[XmlNode], vars: &mut HashMap<String, String>) {
        for node in nodes {
            if node.name.eq_ignore_ascii_case("var") {
                if let Some(var_name) = node.get_attribute("name") {
                    vars.insert(var_name.to_string(), node.content.clone());
                }
            }
            Self::collect_vars_recursive(&node.children, vars);
        }
    }

    fn substitute_vars_recursive(node: &mut XmlNode, vars: &HashMap<String, String>) {
        // Substitute in content
        for (var_name, var_val) in vars {
            let pattern = format!("${}", var_name);
            if node.content.contains(&pattern) {
                node.content = node.content.replace(&pattern, var_val);
            }
        }

        // Substitute in attributes
        for attr_val in node.attributes.values_mut() {
            for (var_name, var_val) in vars {
                let pattern = format!("${}", var_name);
                if attr_val.contains(&pattern) {
                    *attr_val = attr_val.replace(&pattern, var_val);
                }
            }
        }

        // Recurse children
        for child in &mut node.children {
            Self::substitute_vars_recursive(child, vars);
        }
    }

    /// Port of `os_xml_access.c: OS_GetElements`:
    /// Traverses the hierarchy along `path` (e.g. `["ossec_config", "syscheck", "directories"]`)
    /// and returns all matching leaf nodes.
    pub fn get_elements_by_path<'a>(&'a self, path: &[&str]) -> Vec<&'a XmlNode> {
        if path.is_empty() {
            return Vec::new();
        }

        let first = path[0];
        let mut current_matches: Vec<&'a XmlNode> = self
            .root_nodes
            .iter()
            .filter(|n| n.name == first)
            .collect();

        for &segment in &path[1..] {
            let mut next_matches = Vec::new();
            for node in current_matches {
                for child in &node.children {
                    if child.name == segment {
                        next_matches.push(child);
                    }
                }
            }
            current_matches = next_matches;
            if current_matches.is_empty() {
                break;
            }
        }

        current_matches
    }

    /// Port of `os_xml_access.c: OS_GetElementContent`:
    /// Returns the text content of the first element found at the given path.
    pub fn get_element_content(&self, path: &[&str]) -> Option<String> {
        let elements = self.get_elements_by_path(path);
        elements.first().map(|n| n.content.clone())
    }

    /// Port of `os_xml_access.c: OS_ElementExist`:
    /// Checks if at least one element exists at the specified path.
    pub fn element_exist(&self, path: &[&str]) -> bool {
        !self.get_elements_by_path(path).is_empty()
    }

    /// Port of `os_xml_access.c: OS_RootElementExist`:
    /// Checks if a root-level element with `root_name` exists.
    pub fn root_element_exist(&self, root_name: &str) -> bool {
        self.root_nodes.iter().any(|n| n.name == root_name)
    }

    /// Port of `os_xml_access.c: OS_GetContents`:
    /// Returns an array of content strings for all matching elements along `path`.
    pub fn get_contents(&self, path: &[&str]) -> Vec<String> {
        self.get_elements_by_path(path)
            .into_iter()
            .map(|n| n.content.clone())
            .collect()
    }

    /// Port of `os_xml_access.c: OS_GetAttributeContent`:
    /// Returns the value of a specific attribute of the first element found at `path`.
    pub fn get_attribute_content(&self, path: &[&str], attr_name: &str) -> Option<String> {
        let elements = self.get_elements_by_path(path);
        elements.first().and_then(|n| n.attributes.get(attr_name).cloned())
    }

    /// Update or insert an element content at the given hierarchical path.
    pub fn set_element_content(&mut self, path: &[&str], value: &str) {
        if path.is_empty() {
            return;
        }

        let first = path[0];
        let root_idx = match self.root_nodes.iter().position(|n| n.name == first) {
            Some(idx) => idx,
            None => {
                self.root_nodes.push(XmlNode::new(first));
                self.root_nodes.len() - 1
            }
        };

        let mut current = &mut self.root_nodes[root_idx];
        for &segment in &path[1..] {
            let child_idx = match current.children.iter().position(|c| c.name == segment) {
                Some(idx) => idx,
                None => {
                    current.children.push(XmlNode::new(segment));
                    current.children.len() - 1
                }
            };
            current = &mut current.children[child_idx];
        }

        current.content = value.to_string();
    }

    /// Port of `os_xml_writer.c: OS_WriteXML`:
    /// Reads `infile`, modifies or appends `nodes` with `new_val`, and writes output to `outfile`.
    pub fn write_xml_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        infile: P1,
        outfile: P2,
        nodes: &[&str],
        _old_val: Option<&str>,
        new_val: &str,
    ) -> Result<(), String> {
        let mut xml = Self::parse_file(infile.as_ref())?;
        xml.set_element_content(nodes, new_val);
        xml.save_to_file(outfile.as_ref())
    }

    /// Port of `os_xml_writer.c: OS_WriteXML`:
    /// Formats the XML DOM tree back into a clean indented XML string.
    pub fn to_xml_string(&self) -> String {
        let mut out = String::new();
        for root in &self.root_nodes {
            Self::render_node(root, 0, &mut out);
        }
        out
    }

    fn render_node(node: &XmlNode, depth: usize, out: &mut String) {
        let indent = "  ".repeat(depth);
        out.push_str(&indent);
        out.push('<');
        out.push_str(&node.name);

        let mut sorted_attrs: Vec<(&String, &String)> = node.attributes.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| (*k).clone());

        for (k, v) in sorted_attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_xml_attr(v));
            out.push('"');
        }

        if node.children.is_empty() && node.content.is_empty() {
            out.push_str("/>\n");
            return;
        }

        out.push('>');

        if !node.children.is_empty() {
            out.push('\n');
            if !node.content.is_empty() {
                out.push_str(&format!("{}  {}\n", indent, escape_xml_text(&node.content)));
            }
            for child in &node.children {
                Self::render_node(child, depth + 1, out);
            }
            out.push_str(&indent);
        } else {
            out.push_str(&escape_xml_text(&node.content));
        }

        out.push_str(&format!("</{}>\n", node.name));
    }

    /// Save XML tree to disk atomically (writes to temp file, then renames).
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");
        let xml_str = self.to_xml_string();

        let mut file = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary file: {}", e))?;
        file.write_all(xml_str.as_bytes())
            .map_err(|e| format!("Failed to write to temporary file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temporary file: {}", e))?;

        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to rename temporary file: {}", e))?;

        Ok(())
    }
}

/// Port of `os_xml.h: w_get_attr_val_by_name`:
/// Retrieve the value of an attribute of a node by name.
pub fn w_get_attr_val_by_name<'a>(node: &'a XmlNode, name: &str) -> Option<&'a str> {
    node.get_attribute(name)
}

fn escape_xml_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_xml_parsing_and_access() {
        let xml = r#"
        <ossec_config>
            <syscheck>
                <disabled>no</disabled>
                <frequency>7200</frequency>
                <directories check_all="yes">/etc,/usr/bin</directories>
                <directories check_all="no">/var/log</directories>
            </syscheck>
        </ossec_config>
        "#;

        let os_xml = OsXml::parse_str(xml).unwrap();
        assert!(os_xml.root_element_exist("ossec_config"));
        assert!(os_xml.element_exist(&["ossec_config", "syscheck", "disabled"]));

        let disabled = os_xml
            .get_element_content(&["ossec_config", "syscheck", "disabled"])
            .unwrap();
        assert_eq!(disabled, "no");

        let dirs = os_xml.get_elements_by_path(&["ossec_config", "syscheck", "directories"]);
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].get_attribute("check_all"), Some("yes"));
        assert_eq!(dirs[0].content, "/etc,/usr/bin");
        assert_eq!(dirs[1].get_attribute("check_all"), Some("no"));
        assert_eq!(dirs[1].content, "/var/log");
    }

    #[test]
    fn test_os_xml_variable_expansion() {
        let xml = r#"
        <group name="web_rules">
            <var name="INTERNAL_NET">192.168.1.0/24</var>
            <var name="ADMIN_USER">sysadmin</var>

            <rule id="100001" level="5">
                <srcip>$INTERNAL_NET</srcip>
                <user expected="$ADMIN_USER">authorized</user>
                <description>Access from $INTERNAL_NET by $ADMIN_USER</description>
            </rule>
        </group>
        "#;

        let os_xml = OsXml::parse_str(xml).unwrap();
        assert_eq!(os_xml.variables.get("INTERNAL_NET").unwrap(), "192.168.1.0/24");
        assert_eq!(os_xml.variables.get("ADMIN_USER").unwrap(), "sysadmin");

        let rule = os_xml.get_elements_by_path(&["group", "rule"]).pop().unwrap();
        let srcip = rule.get_child("srcip").unwrap();
        assert_eq!(srcip.content, "192.168.1.0/24"); // $INTERNAL_NET replaced!

        let desc = rule.get_child("description").unwrap();
        assert_eq!(desc.content, "Access from 192.168.1.0/24 by sysadmin");

        let user = rule.get_child("user").unwrap();
        assert_eq!(user.get_attribute("expected"), Some("sysadmin"));
    }

    #[test]
    fn test_os_xml_writer_roundtrip() {
        let xml = r#"<ossec_config><syscheck><frequency>3600</frequency></syscheck></ossec_config>"#;
        let os_xml = OsXml::parse_str(xml).unwrap();

        let rendered = os_xml.to_xml_string();
        assert!(rendered.contains("<ossec_config>"));
        assert!(rendered.contains("<syscheck>"));
        assert!(rendered.contains("<frequency>3600</frequency>"));

        // Re-parse rendered XML to verify valid roundtrip
        let reparsed = OsXml::parse_str(&rendered).unwrap();
        assert_eq!(
            reparsed.get_element_content(&["ossec_config", "syscheck", "frequency"]),
            Some("3600".to_string())
        );
    }

    #[test]
    fn test_os_xml_advanced_access_and_modification() {
        let xml = r#"
        <root>
            <item id="1">First</item>
            <item id="2">Second</item>
            <server host="10.0.0.1" port="1514"/>
        </root>
        "#;
        let mut os_xml = OsXml::parse_str(xml).unwrap();

        // Test get_contents (multiple items)
        let contents = os_xml.get_contents(&["root", "item"]);
        assert_eq!(contents, vec!["First", "Second"]);

        // Test get_attribute_content
        let host = os_xml.get_attribute_content(&["root", "server"], "host");
        assert_eq!(host, Some("10.0.0.1".to_string()));

        // Test w_get_attr_val_by_name
        let server_nodes = os_xml.get_elements_by_path(&["root", "server"]);
        assert_eq!(server_nodes.len(), 1);
        assert_eq!(w_get_attr_val_by_name(server_nodes[0], "port"), Some("1514"));

        // Test set_element_content
        os_xml.set_element_content(&["root", "server", "protocol"], "udp");
        assert_eq!(
            os_xml.get_element_content(&["root", "server", "protocol"]),
            Some("udp".to_string())
        );

        // Test write_xml_file
        let temp_dir = tempfile::tempdir().unwrap();
        let in_file = temp_dir.path().join("in.xml");
        let out_file = temp_dir.path().join("out.xml");
        std::fs::write(&in_file, xml).unwrap();

        OsXml::write_xml_file(&in_file, &out_file, &["root", "server", "timeout"], None, "60").unwrap();
        let updated = OsXml::parse_file(&out_file).unwrap();
        assert_eq!(
            updated.get_element_content(&["root", "server", "timeout"]),
            Some("60".to_string())
        );
    }
}
