//! Port of `src/os_xml/os_xml_access.c` and `os_xml_node_access.c`.

use crate::{OsXml, XmlNode, XmlType};

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// An `xml_node` with its bytes as stored (no UTF-8 conversion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNode {
    pub key: usize,
    pub element: Vec<u8>,
    pub content: Option<Vec<u8>>,
    /// Empty when the C node's `attributes` is NULL.
    pub attributes: Vec<Vec<u8>>,
    pub values: Vec<Vec<u8>>,
}

impl OsXml {
    /// `OS_GetElementsbyNode` returning raw bytes (`None` key = root elements).
    pub fn get_elements_by_node_raw(&self, key: Option<usize>) -> Option<Vec<RawNode>> {
        let (mut i, m) = match key {
            None => (0usize, 0u32),
            Some(k) => (k + 1, self.rl[k] + 1),
        };
        let mut ret: Option<Vec<RawNode>> = None;
        while i < self.cur() {
            if self.tp[i] == XmlType::Elem && self.rl[i] == m {
                let mut n = RawNode {
                    key: i,
                    element: self.el[i].clone(),
                    content: self.ct[i].clone(),
                    attributes: Vec::new(),
                    values: Vec::new(),
                };
                let mut l = i + 1;
                while l < self.cur() {
                    if self.tp[l] == XmlType::Attr && self.rl[l] == m {
                        if let Some(c) = &self.ct[l] {
                            n.attributes.push(self.el[l].clone());
                            n.values.push(c.clone());
                            l += 1;
                            continue;
                        }
                    }
                    break;
                }
                ret.get_or_insert_with(Vec::new).push(n);
                i += 1;
                continue;
            }
            if self.tp[i] == XmlType::Elem && m > self.rl[i] && key.is_some() {
                break;
            }
            i += 1;
        }
        ret
    }

    /// `OS_ElementExist`: number of times the full path occurs.
    pub fn element_exist(&self, element_name: &[&str]) -> u32 {
        if element_name.is_empty() {
            return 0;
        }
        let name = |j: usize| element_name.get(j).copied();
        let (mut j, mut matched, mut totalmatch) = (0usize, false, 0u32);
        for i in 0..self.cur() {
            if name(j).is_none() {
                j = 0;
            }
            if self.tp[i] == XmlType::Elem && self.rl[i] as usize == j {
                if let Some(n) = name(j) {
                    if self.el[i] == n.as_bytes() {
                        j += 1;
                        matched = true;
                        if name(j).is_none() {
                            j = 0;
                            totalmatch += 1;
                        }
                        continue;
                    }
                }
            }
            if matched && j > self.rl[i] as usize && self.tp[i] == XmlType::Elem {
                j = 0;
                matched = false;
            }
        }
        totalmatch
    }

    /// `OS_RootElementExist`
    pub fn root_element_exist(&self, element_name: &str) -> u32 {
        self.element_exist(&[element_name])
    }

    /// `OS_GetAttributes`
    pub fn get_attributes(&self, element_name: &[&str]) -> Option<Vec<String>> {
        self.get_elements_internal(Some(element_name), XmlType::Attr)
    }

    /// `OS_GetElements` (`None` = root elements).
    pub fn get_elements(&self, element_name: Option<&[&str]>) -> Option<Vec<String>> {
        self.get_elements_internal(element_name, XmlType::Elem)
    }

    /// `_GetElements`
    fn get_elements_internal(&self, element_name: Option<&[&str]>, ty: XmlType) -> Option<Vec<String>> {
        let name = |j: usize| element_name.and_then(|e| e.get(j).copied());
        let mut ready = ty == XmlType::Elem && element_name.is_none();
        let (mut j, mut matched) = (0usize, false);
        let mut ret: Option<Vec<String>> = None;

        for i in 0..self.cur() {
            if !ready && name(j).is_none() {
                if matched {
                    ready = true;
                } else {
                    break;
                }
            }
            if j > 16 {
                return ret;
            }
            if ready && self.tp[i] == ty {
                let ok = (ty == XmlType::Attr && j >= 1 && self.rl[i] as usize == j - 1)
                    || (ty == XmlType::Elem && self.rl[i] as usize == j);
                if ok {
                    ret.get_or_insert_with(Vec::new).push(s(&self.el[i]));
                }
            } else if self.tp[i] == XmlType::Elem && self.rl[i] as usize == j && name(j).is_some() {
                if self.el[i] == name(j).unwrap().as_bytes() {
                    j += 1;
                    matched = true;
                    continue;
                }
            }
            if matched
                && ((self.tp[i] == XmlType::Attr && j > self.rl[i] as usize + 1)
                    || (self.tp[i] == XmlType::Elem && j > self.rl[i] as usize))
            {
                j = 0;
                matched = false;
                ready = element_name.is_none();
            }
        }
        ret
    }

    /// `OS_GetOneContentforElement`
    pub fn get_one_content_for_element(&mut self, element_name: &[&str]) -> Option<String> {
        self.fol = 0;
        self.get_element_content_internal(element_name, None).and_then(|v| v.into_iter().next())
    }

    /// `OS_GetElementContent`
    pub fn get_element_content(&mut self, element_name: &[&str]) -> Option<Vec<String>> {
        self.fol = 0;
        self.get_element_content_internal(element_name, None)
    }

    /// `OS_GetContents`: iterator-style; call with `None` to reset the state.
    pub fn get_contents(&mut self, element_name: Option<&[&str]>) -> Option<Vec<String>> {
        match element_name {
            None => {
                self.fol = -1;
                None
            }
            Some(e) => self.get_element_content_internal(e, None),
        }
    }

    /// `OS_GetAttributeContent`
    pub fn get_attribute_content(&mut self, element_name: &[&str], attribute_name: &str) -> Option<String> {
        self.fol = 0;
        self.get_element_content_internal(element_name, Some(attribute_name))
            .and_then(|v| v.into_iter().next())
    }

    /// `_GetElementContent`
    fn get_element_content_internal(&mut self, element_name: &[&str], attr: Option<&str>) -> Option<Vec<String>> {
        let cur = self.cur() as i64;
        if self.fol >= 0 && self.fol == cur {
            self.fol = 0;
            return None;
        }
        let start: i64 = if self.fol > 0 {
            let mut i = self.fol;
            while i >= 0 {
                self.fol = i;
                if self.rl[i as usize] == 0 {
                    break;
                }
                i -= 1;
            }
            self.fol
        } else {
            0
        };

        let name = |j: usize| element_name.get(j).copied();
        let mut ret: Option<Vec<String>> = None;
        let (mut j, mut matched) = (0usize, false);
        let mut l: i64 = start;
        while l < cur {
            let lu = l as usize;
            if name(j).is_none() && !matched {
                break;
            }
            if j > 16 {
                return None;
            }
            if self.tp[lu] != XmlType::Elem || self.rl[lu] as usize != j {
                if j > self.rl[lu] as usize {
                    j = 0;
                    matched = false;
                    l -= 1;
                }
                l += 1;
                continue;
            } else if name(j).is_some() && self.el[lu] == name(j).unwrap().as_bytes() {
                j += 1;
                matched = true;
                if name(j).is_none() {
                    let mut target = lu;
                    if let Some(a) = attr {
                        for m in lu + 1..self.cur() {
                            if self.tp[m] == XmlType::Elem {
                                break;
                            }
                            if self.el[m] == a.as_bytes() {
                                target = m;
                                l = m as i64;
                                break;
                            }
                        }
                    }
                    if let Some(c) = &self.ct[target] {
                        ret.get_or_insert_with(Vec::new).push(s(c));
                        matched = true;
                        if attr.is_some() {
                            break;
                        } else if self.fol != 0 {
                            self.fol = l + 1;
                            break;
                        }
                    }
                    let lu = l as usize;
                    if lu + 1 < self.cur() && self.tp[lu + 1] == XmlType::Elem {
                        j = self.rl[lu + 1] as usize;
                    }
                }
                l += 1;
                continue;
            }
            if j > self.rl[lu] as usize {
                j = 0;
                matched = false;
            }
            l += 1;
        }
        ret
    }

    /// `OS_GetElementsbyNode` (`None` = root elements).
    pub fn get_elements_by_node(&self, node: Option<&XmlNode>) -> Option<Vec<XmlNode>> {
        let (mut i, m) = match node {
            None => (0usize, 0u32),
            Some(n) => {
                let i = n.key;
                (i + 1, self.rl[i] + 1)
            }
        };
        let mut ret: Option<Vec<XmlNode>> = None;
        while i < self.cur() {
            if self.tp[i] == XmlType::Elem && self.rl[i] == m {
                let mut n = XmlNode {
                    key: i,
                    element: s(&self.el[i]),
                    content: self.ct[i].as_ref().map(|c| s(c)),
                    attributes: Vec::new(),
                    values: Vec::new(),
                };
                let mut l = i + 1;
                while l < self.cur() {
                    if self.tp[l] == XmlType::Attr && self.rl[l] == m {
                        if let Some(c) = &self.ct[l] {
                            n.attributes.push(s(&self.el[l]));
                            n.values.push(s(c));
                            l += 1;
                            continue;
                        }
                    }
                    break;
                }
                ret.get_or_insert_with(Vec::new).push(n);
                i += 1;
                continue;
            }
            if self.tp[i] == XmlType::Elem && m > self.rl[i] && node.is_some() {
                break;
            }
            i += 1;
        }
        ret
    }
}
