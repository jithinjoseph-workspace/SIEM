//! `<labels>` (config/labels-config.c, `Read_Labels`) and the `labels_*`
//! helpers of shared/labels_op.c.

use crate::messages;
use crate::{ConfigContext, ConfigError, Result};
use siem_xml::XmlNode;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LabelFlags {
    pub hidden: bool,
    pub system: bool,
}

/// `wlabel_t`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Label {
    pub key: String,
    pub value: String,
    pub flags: LabelFlags,
}

/// `labels_add`: with `overwrite`, an existing key gets the new value/flags.
pub fn labels_add(labels: &mut Vec<Label>, key: &str, value: &str, flags: LabelFlags, overwrite: bool) {
    if overwrite {
        if let Some(l) = labels.iter_mut().find(|l| l.key == key) {
            l.value = value.to_string();
            l.flags = flags;
            return;
        }
    }
    labels.push(Label { key: key.to_string(), value: value.to_string(), flags });
}

/// `labels_get`
pub fn labels_get<'a>(labels: &'a [Label], key: &str) -> Option<&'a str> {
    labels.iter().find(|l| l.key == key).map(|l| l.value.as_str())
}

/// `Read_Labels`. On error the label list is cleared (`labels_free`).
pub fn read_labels(ctx: &mut ConfigContext, nodes: &[XmlNode], labels: &mut Vec<Label>) -> Result<()> {
    let r = (|| {
        for n in nodes {
            let Some(content) = n.content.as_deref() else {
                return Err(ConfigError::new(messages::xml_valuenull(&n.element)));
            };
            if n.element != "label" {
                return Err(ConfigError::new(messages::xml_invelem(&n.element)));
            }
            let mut key: Option<&str> = None;
            let mut flags = LabelFlags::default();
            for (j, a) in n.attributes.iter().enumerate() {
                let v = n.values[j].as_str();
                if a == "key" {
                    if !v.is_empty() {
                        if v.starts_with('_') {
                            ctx.warn(format!(
                                "Label keys starting with \"_\"  are reserved for internal use. Skipping label '{v}'."
                            ));
                            flags.system = true;
                        }
                        key = Some(v);
                    } else {
                        return Err(ConfigError::new("Label with empty key."));
                    }
                } else if a == "hidden" {
                    flags.hidden = match v {
                        "yes" => true,
                        "no" => false,
                        _ => return Err(ConfigError::new(format!("Invalid content for attribute '{a}'."))),
                    };
                }
            }
            if flags.system {
                continue;
            }
            let Some(key) = key else {
                return Err(ConfigError::new("Expected 'key' attribute for label."));
            };
            if content.is_empty() {
                ctx.warn(format!("Label '{key}' is empty."));
            }
            labels_add(labels, key, content, flags, true);
        }
        Ok(())
    })();
    if r.is_err() {
        labels.clear();
    }
    r
}

/// `labels_parse`: labels from wazuh-db (`[{"key":..,"value":..}]`). The
/// stored keys are quoted: `"k"` normal, `!"k"` hidden, `#"k"` internal
/// (system); anything else is skipped, and the key ends at the next quote.
pub fn labels_parse(json: &siem_cjson::Json) -> Vec<Label> {
    let mut out = Vec::new();
    for item in json.children() {
        let (Some(siem_cjson::Json::String(k)), Some(siem_cjson::Json::String(v))) =
            (item.get_exact("key"), item.get_exact("value"))
        else {
            continue;
        };
        let (start, flags) = match (k.first(), k.get(1)) {
            (Some(b'!'), Some(b'"')) => (2, LabelFlags { hidden: true, system: false }),
            (Some(b'#'), Some(b'"')) => (2, LabelFlags { hidden: false, system: true }),
            (Some(b'"'), _) => (1, LabelFlags::default()),
            _ => continue,
        };
        let rest = &k[start..];
        let Some(end) = rest.iter().position(|&c| c == b'"') else {
            continue;
        };
        let key = String::from_utf8_lossy(&rest[..end]).into_owned();
        let value = String::from_utf8_lossy(v).into_owned();
        labels_add(&mut out, &key, &value, flags, false);
    }
    out
}
