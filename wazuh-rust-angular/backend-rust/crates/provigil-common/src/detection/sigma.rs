// SIGMA-compatible Detection Rule Engine
// Lightweight fresh implementation — NOT based on any existing SIGMA codebase.
// Supports: equals, contains, startswith, endswith, re, cidr,
//           named selections, any/all of <pattern>, not, AND/OR expressions.
// License: Apache-2.0

use crate::normalizer::NormalizedEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

// ── Primitive types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub product:  Option<String>,
    pub category: Option<String>,
    pub service:  Option<String>,
}

#[derive(Debug, Clone)]
pub enum Matcher { Equals, Contains, StartsWith, EndsWith, Regex, Cidr }

#[derive(Debug, Clone)]
pub struct FieldCondition {
    pub field:          String,
    pub matcher:        Matcher,
    pub values:         Vec<String>,
    pub compiled_regex: Vec<Option<Arc<Regex>>>,
    pub negated:        bool,
}

impl FieldCondition {
    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        if self.field == "*" {
            let raw = event.raw.to_string().to_lowercase();
            let hit = self.values.iter().any(|val| raw.contains(&val.to_lowercase()));
            return if self.negated { !hit } else { hit };
        }

        let field_val = match event.get_field(&self.field) {
            Some(v) => v.to_lowercase(),
            None    => return self.negated,
        };
        let hit = self.values.iter().enumerate().any(|(i, val)| {
            let v = val.to_lowercase();
            match &self.matcher {
                Matcher::Equals     => field_val == v,
                Matcher::Contains   => field_val.contains(&v),
                Matcher::StartsWith => field_val.starts_with(&v),
                Matcher::EndsWith   => field_val.ends_with(&v),
                Matcher::Cidr       => ip_in_cidr(&field_val, val),
                Matcher::Regex      => self.compiled_regex
                    .get(i)
                    .and_then(|o| o.as_ref())
                    .map(|r| r.is_match(&field_val))
                    .unwrap_or_else(|| Regex::new(val).map(|r| r.is_match(&field_val)).unwrap_or(false)),
            }
        });
        if self.negated { !hit } else { hit }
    }
}

#[derive(Debug, Clone)]
pub enum Logic { And, Or }

// ── Named selection group ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SelectionGroup {
    pub alternatives: Vec<Vec<FieldCondition>>,
}

impl SelectionGroup {
    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        self.alternatives.iter().any(|alt| alt.iter().all(|c| c.matches(event)))
    }
}

// ── Condition expression AST ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ConditionExpr {
    Named(String),
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    AnyOf(String),
    AllOf(String),
    AnyOfThem,
    AllOfThem,
    AlwaysTrue,
    AlwaysFalse,
    Unsupported(String),
}

impl ConditionExpr {
    pub fn eval(&self, selections: &HashMap<String, SelectionGroup>, event: &NormalizedEvent) -> bool {
        match self {
            ConditionExpr::Named(name) =>
                selections.get(name).map(|g| g.matches(event)).unwrap_or(false),
            ConditionExpr::Not(inner) =>
                !inner.eval(selections, event),
            ConditionExpr::And(parts) =>
                parts.iter().all(|p| p.eval(selections, event)),
            ConditionExpr::Or(parts) =>
                parts.iter().any(|p| p.eval(selections, event)),
            ConditionExpr::AnyOf(prefix) =>
                selections.iter()
                    .filter(|(k, _)| k.starts_with(prefix.as_str()))
                    .any(|(_, g)| g.matches(event)),
            ConditionExpr::AllOf(prefix) => {
                let matching: Vec<_> = selections.iter()
                    .filter(|(k, _)| k.starts_with(prefix.as_str()))
                    .collect();
                !matching.is_empty() && matching.iter().all(|(_, g)| g.matches(event))
            }
            ConditionExpr::AnyOfThem =>
                selections.values().any(|g| g.matches(event)),
            ConditionExpr::AllOfThem =>
                !selections.is_empty() && selections.values().all(|g| g.matches(event)),
            ConditionExpr::AlwaysTrue      => true,
            ConditionExpr::AlwaysFalse     => false,
            ConditionExpr::Unsupported(_)  => false,
        }
    }
}

// ── SigmaRule ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SigmaRule {
    pub id:             String,
    pub title:          String,
    pub severity:       String,
    pub tags:           Vec<String>,
    pub logsource:      LogSource,
    pub selections:     HashMap<String, SelectionGroup>,
    pub condition_expr: ConditionExpr,
    pub conditions:     Vec<FieldCondition>,
    pub logic:          Logic,
    pub tenant_id:      String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatch {
    pub rule_id:  String,
    pub title:    String,
    pub severity: String,
    pub tags:     Vec<String>,
}

// ── Condition expression parser ───────────────────────────────────────────

fn tokenize_condition(s: &str) -> Vec<String> {
    let mut tokens = Vec::<String>::new();
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' | ')' => {
                let t = cur.trim().to_string();
                if !t.is_empty() { tokens.push(t); }
                cur.clear();
                tokens.push(ch.to_string());
            }
            ' ' | '\t' => {
                let t = cur.trim().to_string();
                if !t.is_empty() { tokens.push(t); }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() { tokens.push(t); }
    tokens
}

pub fn parse_condition_expr(s: &str) -> ConditionExpr {
    if s.contains("count(") || s.starts_with("near ") || s.contains("| within") {
        return ConditionExpr::Unsupported(s.trim().to_string());
    }
    let tokens = tokenize_condition(s);
    if tokens.is_empty() { return ConditionExpr::AlwaysTrue; }
    let (expr, _) = parse_or(&tokens, 0);
    expr
}

fn parse_or(tokens: &[String], pos: usize) -> (ConditionExpr, usize) {
    let (mut left, mut pos) = parse_and(tokens, pos);
    while pos < tokens.len() && tokens[pos].to_lowercase() == "or" {
        pos += 1;
        let (right, new_pos) = parse_and(tokens, pos);
        pos = new_pos;
        left = match left {
            ConditionExpr::Or(mut parts) => { parts.push(right); ConditionExpr::Or(parts) }
            _ => ConditionExpr::Or(vec![left, right]),
        };
    }
    (left, pos)
}

fn parse_and(tokens: &[String], pos: usize) -> (ConditionExpr, usize) {
    let (mut left, mut pos) = parse_not(tokens, pos);
    while pos < tokens.len() && tokens[pos].to_lowercase() == "and" {
        pos += 1;
        let (right, new_pos) = parse_not(tokens, pos);
        pos = new_pos;
        left = match left {
            ConditionExpr::And(mut parts) => { parts.push(right); ConditionExpr::And(parts) }
            _ => ConditionExpr::And(vec![left, right]),
        };
    }
    (left, pos)
}

fn parse_not(tokens: &[String], pos: usize) -> (ConditionExpr, usize) {
    if pos < tokens.len() && tokens[pos].to_lowercase() == "not" {
        let (inner, new_pos) = parse_not(tokens, pos + 1);
        return (ConditionExpr::Not(Box::new(inner)), new_pos);
    }
    parse_quantifier(tokens, pos)
}

fn parse_quantifier(tokens: &[String], pos: usize) -> (ConditionExpr, usize) {
    if pos + 1 < tokens.len() {
        let tok  = tokens[pos].to_lowercase();
        let next = tokens[pos + 1].to_lowercase();
        if next == "of" && (tok == "any" || tok == "all" || tok == "1") {
            if pos + 2 < tokens.len() {
                let pattern = &tokens[pos + 2];
                let is_all  = tok == "all";
                let expr = if pattern.to_lowercase() == "them" {
                    if is_all { ConditionExpr::AllOfThem } else { ConditionExpr::AnyOfThem }
                } else if pattern.ends_with('*') {
                    let prefix = pattern.trim_end_matches('*').to_string();
                    if is_all { ConditionExpr::AllOf(prefix) } else { ConditionExpr::AnyOf(prefix) }
                } else {
                    ConditionExpr::Named(pattern.clone())
                };
                return (expr, pos + 3);
            }
        }
    }
    parse_atom(tokens, pos)
}

fn parse_atom(tokens: &[String], pos: usize) -> (ConditionExpr, usize) {
    if pos >= tokens.len() {
        return (ConditionExpr::AlwaysTrue, pos);
    }
    if tokens[pos] == "(" {
        let (inner, new_pos) = parse_or(tokens, pos + 1);
        let close = if new_pos < tokens.len() && tokens[new_pos] == ")" { new_pos + 1 } else { new_pos };
        return (inner, close);
    }
    (ConditionExpr::Named(tokens[pos].clone()), pos + 1)
}

// ── Selection group parser ────────────────────────────────────────────────

fn parse_selection_group(val: &serde_yaml::Value) -> SelectionGroup {
    match val {
        serde_yaml::Value::Sequence(seq) => {
            let alternatives = seq.iter()
                .filter_map(|item| item.as_mapping().map(|map| {
                    let mut alt = Vec::new();
                    for (fk, fv) in map {
                        if let Some(fk_str) = fk.as_str() {
                            parse_field_condition(fk_str, fv, &mut alt);
                        }
                    }
                    alt
                }))
                .collect();
            SelectionGroup { alternatives }
        }
        serde_yaml::Value::Mapping(map) => {
            let mut alt = Vec::new();
            for (fk, fv) in map {
                if let Some(fk_str) = fk.as_str() {
                    parse_field_condition(fk_str, fv, &mut alt);
                }
            }
            SelectionGroup { alternatives: vec![alt] }
        }
        serde_yaml::Value::String(s) => {
            let cond = FieldCondition {
                field:          "*".to_string(),
                matcher:        Matcher::Contains,
                values:         vec![s.clone()],
                compiled_regex: vec![],
                negated:        false,
            };
            SelectionGroup { alternatives: vec![vec![cond]] }
        }
        _ => SelectionGroup { alternatives: vec![] },
    }
}

// ── Loader ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn load_rules_from_dir(dir: impl AsRef<Path>) -> Vec<SigmaRule> {
    let mut rules = Vec::new();
    let dir = dir.as_ref();
    if !dir.exists() { return rules; }

    let Ok(entries) = std::fs::read_dir(dir) else { return rules; };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" { continue; }

        match parse_rule_file(&path) {
            Ok(rule) => { info!("SIGMA rule loaded: {} [{}]", rule.title, rule.id); rules.push(rule); }
            Err(e)   => warn!("Failed to parse {:?}: {}", path, e),
        }
    }
    rules
}

#[allow(dead_code)]
fn parse_rule_file(path: &Path) -> anyhow::Result<SigmaRule> {
    let content = std::fs::read_to_string(path)?;
    parse_rule_content(&content)
}

pub fn parse_rule_content(content: &str) -> anyhow::Result<SigmaRule> {
    let doc: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(content)?;

    let get_str = |k: &str| -> String {
        doc.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };

    let tags = doc.get("tags")
        .and_then(|v| v.as_sequence())
        .map(|s| s.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default();

    let logsource = doc.get("logsource")
        .and_then(|v| v.as_mapping())
        .map(|m| LogSource {
            product:  m.get("product").and_then(|v| v.as_str()).map(String::from),
            category: m.get("category").and_then(|v| v.as_str()).map(String::from),
            service:  m.get("service").and_then(|v| v.as_str()).map(String::from),
        })
        .unwrap_or(LogSource { product: None, category: None, service: None });

    let detection_val = doc.get("detection")
        .ok_or_else(|| anyhow::anyhow!("Missing 'detection' block"))?;

    let condition_str = detection_val.as_mapping()
        .and_then(|m| m.get("condition"))
        .and_then(|v| v.as_str())
        .unwrap_or("selection");

    let condition_expr = parse_condition_expr(condition_str);

    if let ConditionExpr::Unsupported(ref cond) = condition_expr {
        let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or("unknown");
        return Err(anyhow::anyhow!(
            "[SIGMA SKIP] rule \"{}\" uses unsupported aggregation/temporal condition: '{}' \
             — rewrite as a ClickHouse multiflow query or remove the rule",
            title, cond
        ));
    }

    let mut selections: HashMap<String, SelectionGroup> = HashMap::new();
    if let Some(mapping) = detection_val.as_mapping() {
        for (key, val) in mapping {
            let key_str = key.as_str().unwrap_or("");
            if key_str == "condition" { continue; }
            selections.insert(key_str.to_string(), parse_selection_group(val));
        }
    }

    let conditions: Vec<FieldCondition> = selections.values()
        .flat_map(|g| g.alternatives.iter().flat_map(|alt| alt.iter().cloned()))
        .collect();

    let logic = if condition_str.contains("all") { Logic::And } else { Logic::Or };

    Ok(SigmaRule {
        id: get_str("id"), title: get_str("title"),
        severity: get_str("level"), tags, logsource,
        selections, condition_expr,
        conditions, logic,
        tenant_id: "*".to_string(),
    })
}

fn parse_field_condition(field_modifier: &str, value: &serde_yaml::Value, out: &mut Vec<FieldCondition>) {
    let parts: Vec<&str> = field_modifier.splitn(2, '|').collect();
    let field    = parts[0].to_string();
    let modifier = parts.get(1).copied().unwrap_or("equals");
    let negated  = modifier.ends_with("not");

    let matcher = match modifier.trim_end_matches("|not") {
        "contains"   => Matcher::Contains,
        "startswith" => Matcher::StartsWith,
        "endswith"   => Matcher::EndsWith,
        "re"         => Matcher::Regex,
        "cidr"       => Matcher::Cidr,
        _            => Matcher::Equals,
    };

    let values: Vec<String> = match value {
        serde_yaml::Value::String(s)   => vec![s.clone()],
        serde_yaml::Value::Number(n)   => vec![n.to_string()],
        serde_yaml::Value::Sequence(s) =>
            s.iter().filter_map(|v| v.as_str()).map(String::from).collect(),
        _ => return,
    };

    if !values.is_empty() {
        let compiled_regex = if matches!(matcher, Matcher::Regex) {
            values.iter().map(|v| Regex::new(v).ok().map(Arc::new)).collect()
        } else {
            vec![]
        };
        out.push(FieldCondition { field, matcher, values, compiled_regex, negated });
    }
}

// ── CIDR helper ──────────────────────────────────────────────────────────

fn ip_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    use std::net::IpAddr;

    let (network_str, prefix_len_str) = match cidr_str.rsplit_once('/') {
        Some(pair) => pair,
        None => return ip_str == cidr_str,
    };

    let prefix_len: u32 = match prefix_len_str.parse() {
        Ok(n)  => n,
        Err(_) => return false,
    };

    let network_addr: IpAddr = match network_str.parse() {
        Ok(a)  => a,
        Err(_) => return false,
    };

    let host_addr: IpAddr = match ip_str.parse() {
        Ok(a)  => a,
        Err(_) => return false,
    };

    match (network_addr, host_addr) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            if prefix_len > 32 { return false; }
            let shift = 32u32.saturating_sub(prefix_len);
            (u32::from(net) >> shift) == (u32::from(host) >> shift)
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            if prefix_len > 128 { return false; }
            let shift = 128u32.saturating_sub(prefix_len);
            (u128::from(net) >> shift) == (u128::from(host) >> shift)
        }
        _ => false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::normalizer::EventSource;

    fn make_event(fields: &[(&str, &str)]) -> NormalizedEvent {
        let mut raw_map = serde_json::Map::new();
        for (k, v) in fields {
            raw_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        let raw = serde_json::Value::Object(raw_map);

        let get = |key: &str| -> Option<String> {
            fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
        };

        NormalizedEvent {
            source_ip:        get("src_ip").or_else(|| get("source_ip")),
            source_port:      None,
            dest_ip:          get("dst_ip").or_else(|| get("dest_ip")),
            dest_port:        get("dst_port").or_else(|| get("dest_port"))
                                  .and_then(|v| v.parse::<u16>().ok()),
            proto:            get("proto"),
            network_protocol: None,
            community_id:     Some("test-cid".to_string()),
            event_source:     EventSource::Unknown,
            log_source:       None,
            timestamp:        0,
            uid:              None,
            conn_state:       None,
            event_type:       get("event_type"),
            alert:            None,
            raw,
            ..NormalizedEvent::blank()
        }
    }

    // ── Condition expression parser tests ─────────────────────────────────

    #[test]
    fn test_single_named() {
        let expr = parse_condition_expr("selection");
        assert!(matches!(expr, ConditionExpr::Named(n) if n == "selection"));
    }

    #[test]
    fn test_and_expr() {
        let expr = parse_condition_expr("selection and filter");
        assert!(matches!(expr, ConditionExpr::And(_)));
        if let ConditionExpr::And(parts) = expr {
            assert_eq!(parts.len(), 2);
            assert!(matches!(&parts[0], ConditionExpr::Named(n) if n == "selection"));
            assert!(matches!(&parts[1], ConditionExpr::Named(n) if n == "filter"));
        }
    }

    #[test]
    fn test_or_expr() {
        let expr = parse_condition_expr("sel1 or sel2");
        assert!(matches!(expr, ConditionExpr::Or(_)));
        if let ConditionExpr::Or(parts) = expr {
            assert_eq!(parts.len(), 2);
        }
    }

    #[test]
    fn test_not_expr() {
        let expr = parse_condition_expr("selection and not filter");
        assert!(matches!(expr, ConditionExpr::And(_)));
        if let ConditionExpr::And(parts) = expr {
            assert!(matches!(&parts[1], ConditionExpr::Not(_)));
        }
    }

    #[test]
    fn test_any_of_glob() {
        let expr = parse_condition_expr("any of selection*");
        assert!(matches!(expr, ConditionExpr::AnyOf(p) if p == "selection"));
    }

    #[test]
    fn test_all_of_glob() {
        let expr = parse_condition_expr("all of selection*");
        assert!(matches!(expr, ConditionExpr::AllOf(p) if p == "selection"));
    }

    #[test]
    fn test_any_of_them() {
        let expr = parse_condition_expr("any of them");
        assert!(matches!(expr, ConditionExpr::AnyOfThem));
    }

    #[test]
    fn test_all_of_them() {
        let expr = parse_condition_expr("all of them");
        assert!(matches!(expr, ConditionExpr::AllOfThem));
    }

    #[test]
    fn test_count_unsupported_becomes_unsupported() {
        let expr = parse_condition_expr("selection | count() > 10");
        assert!(matches!(expr, ConditionExpr::Unsupported(_)));
    }

    #[test]
    fn test_near_unsupported() {
        let expr = parse_condition_expr("near selection");
        assert!(matches!(expr, ConditionExpr::Unsupported(_)));
    }

    #[test]
    fn test_within_unsupported() {
        let expr = parse_condition_expr("selection | within 5m");
        assert!(matches!(expr, ConditionExpr::Unsupported(_)));
    }

    #[test]
    fn test_nested_parens() {
        let expr = parse_condition_expr("(sel_a or sel_b) and not filter");
        assert!(matches!(expr, ConditionExpr::And(_)));
        if let ConditionExpr::And(parts) = expr {
            assert_eq!(parts.len(), 2);
            assert!(matches!(&parts[0], ConditionExpr::Or(_)));
            assert!(matches!(&parts[1], ConditionExpr::Not(_)));
        }
    }

    #[test]
    fn test_operator_precedence_and_over_or() {
        let expr = parse_condition_expr("sel_a or sel_b and filter");
        assert!(matches!(expr, ConditionExpr::Or(_)));
        if let ConditionExpr::Or(parts) = expr {
            assert!(matches!(&parts[0], ConditionExpr::Named(n) if n == "sel_a"));
            assert!(matches!(&parts[1], ConditionExpr::And(_)));
        }
    }

    #[test]
    fn test_parse_single_selection_rule() {
        let yaml = r#"
title: Test Rule
id: test-001
level: high
logsource:
  product: network
detection:
  selection:
    proto: tcp
    dst_port: "443"
  condition: selection
"#;
        let rule = parse_rule_content(yaml).expect("should parse");
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.severity, "high");
        assert_eq!(rule.selections.len(), 1);
        assert!(rule.selections.contains_key("selection"));
        let grp = &rule.selections["selection"];
        assert_eq!(grp.alternatives.len(), 1);
        assert_eq!(grp.alternatives[0].len(), 2);
    }

    #[test]
    fn test_parse_two_selections_and() {
        let yaml = r#"
title: Two Selections AND
id: test-002
level: medium
logsource:
  product: network
detection:
  selection:
    event_type: alert
  filter:
    proto: udp
  condition: selection and filter
"#;
        let rule = parse_rule_content(yaml).expect("should parse");
        assert_eq!(rule.selections.len(), 2);
        assert!(matches!(rule.condition_expr, ConditionExpr::And(_)));
    }

    #[test]
    fn test_parse_any_of_glob_rule() {
        let yaml = r#"
title: Any Of Glob
id: test-003
level: low
logsource:
  product: network
detection:
  selection_a:
    proto: tcp
  selection_b:
    proto: udp
  condition: any of selection*
"#;
        let rule = parse_rule_content(yaml).expect("should parse");
        assert!(matches!(&rule.condition_expr, ConditionExpr::AnyOf(p) if p == "selection"));
    }

    #[test]
    fn test_parse_list_alternatives() {
        let yaml = r#"
title: List Alternatives
id: test-004
level: medium
logsource:
  product: network
detection:
  selection:
    - proto: tcp
      dst_port: "80"
    - proto: tcp
      dst_port: "443"
  condition: selection
"#;
        let rule = parse_rule_content(yaml).expect("should parse");
        let grp = &rule.selections["selection"];
        assert_eq!(grp.alternatives.len(), 2);
        assert_eq!(grp.alternatives[0].len(), 2);
        assert_eq!(grp.alternatives[1].len(), 2);
    }

    #[test]
    fn test_parse_count_rule_is_rejected() {
        let yaml = r#"
title: Count Rule
id: test-005
level: medium
logsource:
  product: network
detection:
  selection:
    event_type: alert
  condition: selection | count() > 10
"#;
        let err = parse_rule_content(yaml).expect_err("count condition must be rejected");
        assert!(err.to_string().contains("SIGMA SKIP"), "error should mention SIGMA SKIP: {}", err);
    }

    #[test]
    fn test_missing_detection_returns_error() {
        let yaml = r#"
title: No Detection
id: test-006
level: medium
logsource:
  product: network
"#;
        assert!(parse_rule_content(yaml).is_err());
    }

    fn make_selection(field: &str, value: &str) -> SelectionGroup {
        let cond = FieldCondition {
            field:          field.to_string(),
            matcher:        Matcher::Equals,
            values:         vec![value.to_string()],
            compiled_regex: vec![],
            negated:        false,
        };
        SelectionGroup { alternatives: vec![vec![cond]] }
    }

    #[test]
    fn test_eval_named_match() {
        let mut sels = HashMap::new();
        sels.insert("selection".to_string(), make_selection("proto", "tcp"));
        let event = make_event(&[("proto", "tcp")]);
        let expr = ConditionExpr::Named("selection".to_string());
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_named_no_match() {
        let mut sels = HashMap::new();
        sels.insert("selection".to_string(), make_selection("proto", "tcp"));
        let event = make_event(&[("proto", "udp")]);
        let expr = ConditionExpr::Named("selection".to_string());
        assert!(!expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_and() {
        let mut sels = HashMap::new();
        sels.insert("sel".to_string(),    make_selection("proto", "tcp"));
        sels.insert("filter".to_string(), make_selection("dst_port", "443"));
        let event = make_event(&[("proto", "tcp"), ("dst_port", "443")]);
        let expr = ConditionExpr::And(vec![
            ConditionExpr::Named("sel".to_string()),
            ConditionExpr::Named("filter".to_string()),
        ]);
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_and_fails_if_one_missing() {
        let mut sels = HashMap::new();
        sels.insert("sel".to_string(),    make_selection("proto", "tcp"));
        sels.insert("filter".to_string(), make_selection("dst_port", "443"));
        let event = make_event(&[("proto", "tcp"), ("dst_port", "80")]);
        let expr = ConditionExpr::And(vec![
            ConditionExpr::Named("sel".to_string()),
            ConditionExpr::Named("filter".to_string()),
        ]);
        assert!(!expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_or() {
        let mut sels = HashMap::new();
        sels.insert("sel_a".to_string(), make_selection("proto", "tcp"));
        sels.insert("sel_b".to_string(), make_selection("proto", "udp"));
        let event = make_event(&[("proto", "udp")]);
        let expr = ConditionExpr::Or(vec![
            ConditionExpr::Named("sel_a".to_string()),
            ConditionExpr::Named("sel_b".to_string()),
        ]);
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_not() {
        let mut sels = HashMap::new();
        sels.insert("filter".to_string(), make_selection("proto", "udp"));
        let event = make_event(&[("proto", "tcp")]);
        let expr = ConditionExpr::Not(Box::new(ConditionExpr::Named("filter".to_string())));
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_any_of_glob() {
        let mut sels = HashMap::new();
        sels.insert("selection_a".to_string(), make_selection("proto", "tcp"));
        sels.insert("selection_b".to_string(), make_selection("dst_port", "443"));
        let event = make_event(&[("proto", "tcp"), ("dst_port", "80")]);
        let expr = ConditionExpr::AnyOf("selection".to_string());
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_all_of_glob_fails_if_one_misses() {
        let mut sels = HashMap::new();
        sels.insert("selection_a".to_string(), make_selection("proto", "tcp"));
        sels.insert("selection_b".to_string(), make_selection("dst_port", "443"));
        let event = make_event(&[("proto", "tcp"), ("dst_port", "80")]);
        let expr = ConditionExpr::AllOf("selection".to_string());
        assert!(!expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_any_of_them() {
        let mut sels = HashMap::new();
        sels.insert("sel_a".to_string(), make_selection("proto", "tcp"));
        sels.insert("sel_b".to_string(), make_selection("dst_port", "9999"));
        let event = make_event(&[("proto", "tcp")]);
        let expr = ConditionExpr::AnyOfThem;
        assert!(expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_all_of_them() {
        let mut sels = HashMap::new();
        sels.insert("sel_a".to_string(), make_selection("proto", "tcp"));
        sels.insert("sel_b".to_string(), make_selection("dst_port", "9999"));
        let event = make_event(&[("proto", "tcp")]);
        let expr = ConditionExpr::AllOfThem;
        assert!(!expr.eval(&sels, &event));
    }

    #[test]
    fn test_eval_always_true() {
        let sels = HashMap::new();
        let event = make_event(&[]);
        assert!(ConditionExpr::AlwaysTrue.eval(&sels, &event));
    }

    #[test]
    fn test_eval_selection_and_not_filter_full_rule() {
        let yaml = r#"
title: Alert Not UDP
id: eval-001
level: high
logsource:
  product: network
detection:
  selection:
    event_type: alert
  filter:
    proto: udp
  condition: selection and not filter
"#;
        let rule = parse_rule_content(yaml).expect("parse");
        let ev_tcp = make_event(&[("event_type", "alert"), ("proto", "tcp")]);
        assert!(rule.condition_expr.eval(&rule.selections, &ev_tcp), "TCP alert should match");

        let ev_udp = make_event(&[("event_type", "alert"), ("proto", "udp")]);
        assert!(!rule.condition_expr.eval(&rule.selections, &ev_udp), "UDP alert should be filtered");

        let ev_flow = make_event(&[("event_type", "flow"), ("proto", "tcp")]);
        assert!(!rule.condition_expr.eval(&rule.selections, &ev_flow), "Flow should not match");
    }

    #[test]
    fn test_eval_list_alternatives_rule() {
        let yaml = r#"
title: HTTP Ports
id: eval-002
level: medium
logsource:
  product: network
detection:
  selection:
    - dst_port: "80"
    - dst_port: "8080"
    - dst_port: "8443"
  condition: selection
"#;
        let rule = parse_rule_content(yaml).expect("parse");
        let ev_80   = make_event(&[("dst_port", "80")]);
        let ev_8080 = make_event(&[("dst_port", "8080")]);
        let ev_443  = make_event(&[("dst_port", "443")]);

        assert!(rule.condition_expr.eval(&rule.selections, &ev_80),   "port 80 should match");
        assert!(rule.condition_expr.eval(&rule.selections, &ev_8080), "port 8080 should match");
        assert!(!rule.condition_expr.eval(&rule.selections, &ev_443), "port 443 should NOT match");
    }
}
