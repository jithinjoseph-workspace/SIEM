use regex::Regex;
use serde::{Deserialize, Serialize};
use siem_core::DecodedFields;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Raw XML Decoder node representation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawXmlDecoder {
    #[serde(rename = "@name", default)]
    pub name: String,

    #[serde(default)]
    pub parent: Option<String>,

    #[serde(default)]
    pub program_name: Option<String>,

    #[serde(default)]
    pub prematch: Option<String>,

    #[serde(default)]
    pub regex: Option<String>,

    #[serde(default)]
    pub order: Option<String>,
}

/// Compiled Wazuh Decoder for high-speed pattern matching & field extraction
#[derive(Clone)]
pub struct CompiledDecoder {
    pub name: String,
    pub parent: Option<String>,
    pub program_name_regex: Option<Regex>,
    pub prematch_regex: Option<Regex>,
    pub extract_regex: Option<Regex>,
    pub field_order: Vec<String>,
}

impl CompiledDecoder {
    pub fn from_raw(raw: RawXmlDecoder) -> Option<Self> {
        let name = raw.name;
        if name.is_empty() {
            return None;
        }

        let program_name_regex = raw.program_name.and_then(|p| Regex::new(&p).ok());
        let prematch_regex = raw.prematch.and_then(|p| {
            let pat = p.trim_start_matches('^');
            Regex::new(&format!("(?:^|\\s|:\x20){}", pat)).or_else(|_| Regex::new(&p)).ok()
        });
        let extract_regex = raw.regex.and_then(|r| {
            let pat = r.trim_start_matches('^');
            Regex::new(&format!("(?:^|\\s|:\x20){}", pat)).or_else(|_| Regex::new(&r)).ok()
        });

        let field_order = raw
            .order
            .map(|o| {
                o.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            name,
            parent: raw.parent,
            program_name_regex,
            prematch_regex,
            extract_regex,
            field_order,
        })
    }

    /// Try to decode a log line using this compiled decoder
    pub fn try_decode(&self, log: &str, fields: &mut DecodedFields, data: &mut HashMap<String, serde_json::Value>) -> bool {
        // 1. Check program name if present
        if let Some(prog) = &self.program_name_regex {
            if !prog.is_match(log) {
                return false;
            }
        }

        // 2. Check prematch if present
        if let Some(pre) = &self.prematch_regex {
            if !pre.is_match(log) {
                return false;
            }
        }

        // 3. Extract fields if extraction regex is present
        if let Some(rx) = &self.extract_regex {
            if let Some(caps) = rx.captures(log) {
                fields.decoder_name = self.name.clone();
                if let Some(parent) = &self.parent {
                    fields.extra.insert("parent_decoder".to_string(), parent.clone());
                }

                for (idx, field_name) in self.field_order.iter().enumerate() {
                    // Match capture group by 1-based index
                    if let Some(matched_val) = caps.get(idx + 1) {
                        let val_str = matched_val.as_str().to_string();

                        match field_name.as_str() {
                            "srcip" | "src_ip" => fields.src_ip = Some(val_str.clone()),
                            "dstip" | "dst_ip" => fields.dst_ip = Some(val_str.clone()),
                            "srcport" | "src_port" => {
                                if let Ok(p) = val_str.parse::<u16>() {
                                    fields.src_port = Some(p);
                                }
                            }
                            "dstport" | "dst_port" => {
                                if let Ok(p) = val_str.parse::<u16>() {
                                    fields.dst_port = Some(p);
                                }
                            }
                            "user" | "srcuser" | "dstuser" => fields.user = Some(val_str.clone()),
                            "action" => fields.action = Some(val_str.clone()),
                            "status" => fields.status = Some(val_str.clone()),
                            "url" => {
                                fields.extra.insert("url".into(), val_str.clone());
                            }
                            "id" => {
                                fields.extra.insert("id".into(), val_str.clone());
                            }
                            _ => {
                                fields.extra.insert(field_name.clone(), val_str.clone());
                            }
                        }

                        data.insert(field_name.clone(), serde_json::Value::String(val_str));
                    }
                }
                return true;
            }
        } else if self.prematch_regex.is_some() || self.program_name_regex.is_some() {
            fields.decoder_name = self.name.clone();
            return true;
        }

        false
    }
}

/// Helper to parse decoders from a Wazuh XML string or file
pub fn parse_decoders_xml(xml: &str) -> Vec<CompiledDecoder> {
    let mut decoders = Vec::new();

    // Wrap in dummy root if needed to allow parsing multiple <decoder> tags
    let wrapped_xml = if !xml.trim_start().starts_with("<decoders>") {
        format!("<decoders>{}</decoders>", xml)
    } else {
        xml.to_string()
    };

    #[derive(Deserialize)]
    struct DecodersContainer {
        #[serde(default, rename = "decoder")]
        decoder: Vec<RawXmlDecoder>,
    }

    if let Ok(container) = quick_xml::de::from_str::<DecodersContainer>(&wrapped_xml) {
        for raw in container.decoder {
            if let Some(compiled) = CompiledDecoder::from_raw(raw) {
                decoders.push(compiled);
            }
        }
    }

    decoders
}

/// Load decoders from an XML file
pub fn load_decoders_file<P: AsRef<Path>>(path: P) -> Result<Vec<CompiledDecoder>, String> {
    let content = fs::read_to_string(path.as_ref())
        .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
    Ok(parse_decoders_xml(&content))
}
