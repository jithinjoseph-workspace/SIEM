use regex::Regex;
use serde::{Deserialize, Serialize};
use siem_core::{MitreAttack, Rule, RuleAlertInfo};
use std::fs;
use std::path::Path;

/// Raw XML Rule representation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawXmlRule {
    #[serde(rename = "@id", default)]
    pub id: u32,

    #[serde(rename = "@level", default)]
    pub level: u8,

    #[serde(rename = "@noalert", default)]
    pub noalert: Option<String>,

    #[serde(rename = "@frequency", default)]
    pub frequency: Option<u32>,

    #[serde(rename = "@timeframe", default)]
    pub timeframe: Option<u32>,

    #[serde(default)]
    pub if_sid: Option<u32>,

    #[serde(default)]
    pub if_matched_sid: Option<u32>,

    #[serde(default)]
    pub if_matched_group: Option<String>,

    #[serde(default, rename = "same_source_ip")]
    pub same_source_ip: Option<serde_json::Value>,

    #[serde(default, rename = "same_user")]
    pub same_user: Option<serde_json::Value>,

    #[serde(default)]
    pub decoded_as: Option<String>,

    #[serde(default, rename = "match")]
    pub match_pattern: Option<String>,

    #[serde(default)]
    pub regex: Option<String>,

    #[serde(default)]
    pub if_group: Option<String>,

    #[serde(default, rename = "field")]
    pub field_items: Vec<RawXmlField>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default, rename = "group")]
    pub groups: Vec<String>,

    #[serde(default)]
    pub mitre: Option<RawMitre>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawXmlField {
    #[serde(rename = "@name", default)]
    pub name: String,
    #[serde(rename = "$text", default)]
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawMitre {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub tactic: Option<String>,
    #[serde(default)]
    pub technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawXmlGroup {
    #[serde(rename = "@name", default)]
    pub name: String,

    #[serde(default, rename = "rule")]
    pub rules: Vec<RawXmlRule>,
}

/// Compiled Wazuh Rule for real-time evaluation
#[derive(Clone)]
pub struct CompiledWazuhRule {
    pub id: u32,
    pub level: u8,
    pub noalert: bool,
    pub if_sid: Option<u32>,
    pub if_group: Option<String>,
    pub if_matched_sid: Option<u32>,
    pub if_matched_group: Option<String>,
    pub frequency: Option<u32>,
    pub timeframe: Option<u32>,
    pub same_source_ip: bool,
    pub same_user: bool,
    pub decoded_as: Option<String>,
    pub match_pattern: Option<String>,
    pub regex_pattern: Option<Regex>,
    pub field_checks: Vec<(String, Option<Regex>)>,
    pub description: String,
    pub groups: Vec<String>,
    pub mitre: Option<MitreAttack>,
}

impl CompiledWazuhRule {
    pub fn from_raw(raw: RawXmlRule, parent_group: Option<&str>) -> Option<Self> {
        if raw.id == 0 {
            return None;
        }

        let regex_pattern = raw.regex.and_then(|r| Regex::new(&r).ok());

        let mut groups = Vec::new();
        if let Some(pg) = parent_group {
            for g in pg.split(',') {
                let trimmed = g.trim();
                if !trimmed.is_empty() {
                    groups.push(trimmed.to_string());
                }
            }
        }
        for g_str in raw.groups {
            for g in g_str.split(',') {
                let trimmed = g.trim();
                if !trimmed.is_empty() && !groups.contains(&trimmed.to_string()) {
                    groups.push(trimmed.to_string());
                }
            }
        }

        let mitre = raw.mitre.and_then(|m| {
            m.id.map(|id| MitreAttack {
                id,
                tactic: m.tactic.unwrap_or_else(|| "Security".to_string()),
                technique: m.technique.unwrap_or_else(|| "Detection".to_string()),
            })
        });

        let noalert = raw.noalert.map(|v| v == "1" || v == "yes").unwrap_or(false);

        let mut field_checks = Vec::new();
        for f in raw.field_items {
            if !f.name.is_empty() {
                let rx = Regex::new(&f.pattern).ok();
                field_checks.push((f.name, rx));
            }
        }

        let same_source_ip = raw.same_source_ip.is_some();
        let same_user = raw.same_user.is_some();

        Some(Self {
            id: raw.id,
            level: raw.level,
            noalert,
            if_sid: raw.if_sid,
            if_group: raw.if_group,
            if_matched_sid: raw.if_matched_sid,
            if_matched_group: raw.if_matched_group,
            frequency: raw.frequency,
            timeframe: raw.timeframe,
            same_source_ip,
            same_user,
            decoded_as: raw.decoded_as,
            match_pattern: raw.match_pattern,
            regex_pattern,
            field_checks,
            description: raw.description.unwrap_or_default(),
            groups,
            mitre,
        })
    }

    /// Evaluates if this rule matches a log message, context, and sliding window state
    pub fn matches(
        &self,
        message: &str,
        current_decoder: &str,
        parent_decoder: Option<&str>,
        active_sids: &[u32],
        active_groups: &[String],
        data: &std::collections::HashMap<String, serde_json::Value>,
        accumulator: Option<&crate::accumulator::WazuhAccumulator>,
        agent_id: &str,
        src_ip: Option<&str>,
        user: Option<&str>,
    ) -> bool {
        // Must have at least one criteria
        if self.if_sid.is_none()
            && self.if_group.is_none()
            && self.if_matched_sid.is_none()
            && self.if_matched_group.is_none()
            && self.decoded_as.is_none()
            && self.match_pattern.is_none()
            && self.regex_pattern.is_none()
            && self.field_checks.is_empty()
        {
            return false;
        }

        // 1. Check parent rule (if_sid)
        if let Some(parent_sid) = self.if_sid {
            if !active_sids.contains(&parent_sid) {
                return false;
            }
        }

        // 2. Check parent group (if_group)
        if let Some(ref grp) = self.if_group {
            let found = active_groups.iter().any(|g| g.eq_ignore_ascii_case(grp));
            if !found {
                return false;
            }
        }

        // 3. Stateful correlation on previous SID (if_matched_sid)
        if let Some(prev_sid) = self.if_matched_sid {
            if let Some(acm) = accumulator {
                let tf = self.timeframe.unwrap_or(120) as i64;
                let needed_freq = self.frequency.unwrap_or(2) as usize;
                let count = acm.count_matched_sids(
                    prev_sid,
                    tf,
                    self.same_source_ip,
                    src_ip,
                    self.same_user,
                    user,
                    agent_id,
                );
                if count + 1 < needed_freq {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 4. Stateful correlation on previous group (if_matched_group)
        if let Some(ref prev_grp) = self.if_matched_group {
            if let Some(acm) = accumulator {
                let tf = self.timeframe.unwrap_or(120) as i64;
                let needed_freq = self.frequency.unwrap_or(2) as usize;
                let count = acm.count_matched_groups(
                    prev_grp,
                    tf,
                    self.same_source_ip,
                    src_ip,
                    self.same_user,
                    user,
                    agent_id,
                );
                if count + 1 < needed_freq {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 3. Check decoded_as if specified
        if let Some(dec) = &self.decoded_as {
            let matches_decoder = current_decoder.eq_ignore_ascii_case(dec)
                || parent_decoder.map(|p| p.eq_ignore_ascii_case(dec)).unwrap_or(false)
                || current_decoder.to_lowercase().starts_with(&dec.to_lowercase());
            if !matches_decoder {
                return false;
            }
        }

        // 4. Substring match (supports pipe-separated alternatives like "Failed password|Failed none")
        if let Some(sub) = &self.match_pattern {
            let matches_any = sub.split('|').any(|part| {
                let trimmed = part.trim();
                !trimmed.is_empty() && message.contains(trimmed)
            });
            if !matches_any {
                return false;
            }
        }

        // 5. Regex match
        if let Some(rx) = &self.regex_pattern {
            if !rx.is_match(message) {
                return false;
            }
        }

        // 6. Check field conditions
        for (field_name, rx) in &self.field_checks {
            let val = data.get(field_name).or_else(|| {
                // Try short name without namespace prefix (e.g. win.eventdata.destination -> destination)
                field_name.split('.').last().and_then(|k| data.get(k))
            });

            match val {
                Some(v) => {
                    if let Some(s) = v.as_str() {
                        if let Some(r) = rx {
                            if !r.is_match(s) {
                                return false;
                            }
                        }
                    }
                }
                None => return false, // Field required by rule was not extracted
            }
        }

        true
    }

    pub fn to_rule_alert_info(&self) -> RuleAlertInfo {
        RuleAlertInfo {
            id: self.id,
            level: self.level,
            description: self.description.clone(),
            groups: self.groups.clone(),
            mitre: self.mitre.clone(),
        }
    }

    pub fn to_core_rule(&self) -> Rule {
        Rule {
            id: self.id,
            level: self.level,
            description: self.description.clone(),
            regex_pattern: self
                .regex_pattern
                .as_ref()
                .map(|r| r.as_str().to_string())
                .unwrap_or_else(|| self.match_pattern.clone().unwrap_or_default()),
            groups: self.groups.clone(),
            mitre: self.mitre.clone(),
        }
    }
}

/// Parse rules from an XML string
pub fn parse_rules_xml(xml: &str) -> Vec<CompiledWazuhRule> {
    let mut compiled_rules = Vec::new();

    // Wrap in dummy root if needed
    let wrapped_xml = if !xml.trim_start().starts_with("<ruleset>") {
        format!("<ruleset>{}</ruleset>", xml)
    } else {
        xml.to_string()
    };

    #[derive(Deserialize)]
    struct RulesetContainer {
        #[serde(default, rename = "group")]
        groups: Vec<RawXmlGroup>,

        #[serde(default, rename = "rule")]
        direct_rules: Vec<RawXmlRule>,
    }

    if let Ok(container) = quick_xml::de::from_str::<RulesetContainer>(&wrapped_xml) {
        for group in container.groups {
            for raw in group.rules {
                if let Some(cr) = CompiledWazuhRule::from_raw(raw, Some(&group.name)) {
                    compiled_rules.push(cr);
                }
            }
        }
        for raw in container.direct_rules {
            if let Some(cr) = CompiledWazuhRule::from_raw(raw, None) {
                compiled_rules.push(cr);
            }
        }
    }

    compiled_rules
}

/// Load rules from an XML file
pub fn load_rules_file<P: AsRef<Path>>(path: P) -> Result<Vec<CompiledWazuhRule>, String> {
    let content = fs::read_to_string(path.as_ref())
        .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
    Ok(parse_rules_xml(&content))
}
