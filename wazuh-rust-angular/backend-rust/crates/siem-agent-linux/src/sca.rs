use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaCondition {
    All,
    Any,
    None,
}

pub struct LinuxScaCheck {
    pub id: u32,
    pub title: String,
    pub target_file: String,
    pub rule_type: ScaRuleType,
    pub rationale: String,
}

#[allow(dead_code)]
pub enum ScaRuleType {
    /// Check file exists and file permissions are at most `max_octal`
    FilePermissions { max_octal: u32 },
    /// Check configuration key=value pattern in file
    ConfigFileEntry { key: String, expected: String },
    /// Check kernel parameter via /proc/sys
    SysctlParam { path: String, expected: String },
    /// Evaluate structured CIS YAML rules (`f:`, `d:`, `c:`, `-> r:`, `!r:`, etc.)
    YamlRules {
        condition: ScaCondition,
        rules: Vec<String>,
    },
}

pub struct LinuxScaEngine {
    agent_id: String,
    checks: Vec<LinuxScaCheck>,
}

impl LinuxScaEngine {
    pub fn new(agent_id: String) -> Self {
        let mut all_checks = vec![
            LinuxScaCheck {
                id: 2001,
                title: "CIS 1.1: Ensure permissions on /etc/shadow are 0640 or more restrictive".into(),
                target_file: "/etc/shadow".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o640 },
                rationale: "The /etc/shadow file contains user password hashes and must be protected from unauthorized access.".into(),
            },
            LinuxScaCheck {
                id: 2002,
                title: "CIS 1.2: Ensure permissions on /etc/passwd are 0644 or more restrictive".into(),
                target_file: "/etc/passwd".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o644 },
                rationale: "The /etc/passwd file contains user account details and must only be writable by root.".into(),
            },
            LinuxScaCheck {
                id: 2003,
                title: "CIS 5.2.1: Ensure SSH PermitRootLogin is disabled".into(),
                target_file: "/etc/ssh/sshd_config".into(),
                rule_type: ScaRuleType::ConfigFileEntry {
                    key: "PermitRootLogin".into(),
                    expected: "no".into(),
                },
                rationale: "Disallowing direct root logins via SSH preserves auditability.".into(),
            },
            LinuxScaCheck {
                id: 2004,
                title: "CIS 3.1.1: Ensure IP forwarding is disabled (net.ipv4.ip_forward = 0)".into(),
                target_file: "/proc/sys/net/ipv4/ip_forward".into(),
                rule_type: ScaRuleType::SysctlParam {
                    path: "/proc/sys/net/ipv4/ip_forward".into(),
                    expected: "0".into(),
                },
                rationale: "Endpoints should not route traffic between interfaces unless explicitly configured.".into(),
            },
            LinuxScaCheck {
                id: 2005,
                title: "CIS 3.2.1: Ensure ICMP redirects are not accepted".into(),
                target_file: "/proc/sys/net/ipv4/conf/all/accept_redirects".into(),
                rule_type: ScaRuleType::SysctlParam {
                    path: "/proc/sys/net/ipv4/conf/all/accept_redirects".into(),
                    expected: "0".into(),
                },
                rationale: "ICMP redirects can allow an attacker on the same network to alter routing tables.".into(),
            },
            LinuxScaCheck {
                id: 2006,
                title: "CIS 1.5.1: Ensure core dumps are restricted in /etc/security/limits.conf".into(),
                target_file: "/etc/security/limits.conf".into(),
                rule_type: ScaRuleType::ConfigFileEntry {
                    key: "* hard core".into(),
                    expected: "0".into(),
                },
                rationale: "Core dumps may contain sensitive memory contents including keys and credentials.".into(),
            },
        ];

        let sca_dir = Path::new("/opt/provigil-agent/ruleset/sca");
        if sca_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(sca_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ext = path.extension().and_then(|s| s.to_str());
                    if matches!(ext, Some("yml" | "yaml")) {
                        info!("provigil-sca: Discovered CIS benchmark policy: {}", path.display());
                        Self::parse_cis_yaml(&path, &mut all_checks);
                    }
                }
            }
        }

        Self { agent_id, checks: all_checks }
    }

    pub fn parse_cis_yaml(path: &Path, out_checks: &mut Vec<LinuxScaCheck>) {
        let Ok(file) = File::open(path) else { return };
        let reader = BufReader::new(file);

        let mut in_checks = false;
        let mut cur_id: Option<u32> = None;
        let mut cur_title: Option<String> = None;
        let mut cur_rationale: Option<String> = None;
        let mut cur_condition = ScaCondition::All;
        let mut cur_rules: Vec<String> = Vec::new();
        let mut reading_rules = false;

        let mut flush = |id: &mut Option<u32>,
                     title: &mut Option<String>,
                     rat: &mut Option<String>,
                     cond: &mut ScaCondition,
                     rules: &mut Vec<String>| {
            if let (Some(cid), Some(ctitle)) = (id.take(), title.take()) {
                if !rules.is_empty() {
                    let target = rules
                        .iter()
                        .find_map(|r| extract_rule_target(r))
                        .unwrap_or_else(|| "system".to_string());
                    out_checks.push(LinuxScaCheck {
                        id: cid,
                        title: ctitle,
                        target_file: target,
                        rule_type: ScaRuleType::YamlRules {
                            condition: *cond,
                            rules: std::mem::take(rules),
                        },
                        rationale: rat
                            .take()
                            .unwrap_or_else(|| "CIS Benchmark hardening guideline".into()),
                    });
                }
            }
            *rat = None;
            *cond = ScaCondition::All;
            rules.clear();
        };

        for raw in reader.lines().flatten() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed == "checks:" {
                in_checks = true;
                continue;
            }
            if !in_checks {
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("- id:") {
                flush(&mut cur_id, &mut cur_title, &mut cur_rationale, &mut cur_condition, &mut cur_rules);
                reading_rules = false;
                cur_id = rest.trim().parse::<u32>().ok();
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("id:") {
                if cur_id.is_none() {
                    cur_id = rest.trim().parse::<u32>().ok();
                }
                reading_rules = false;
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("title:") {
                cur_title = Some(unquote_yaml(rest.trim()));
                reading_rules = false;
            } else if let Some(rest) = trimmed.strip_prefix("rationale:") {
                cur_rationale = Some(unquote_yaml(rest.trim()));
                reading_rules = false;
            } else if let Some(rest) = trimmed.strip_prefix("condition:") {
                cur_condition = match unquote_yaml(rest.trim()).to_lowercase().as_str() {
                    "any" => ScaCondition::Any,
                    "none" => ScaCondition::None,
                    _ => ScaCondition::All,
                };
                reading_rules = false;
            } else if trimmed == "rules:" {
                reading_rules = true;
            } else if reading_rules && trimmed.starts_with("- ") {
                cur_rules.push(unquote_yaml(trimmed.trim_start_matches("- ").trim()));
            } else if !trimmed.starts_with('-') && trimmed.contains(':') {
                reading_rules = false;
            }
        }

        flush(&mut cur_id, &mut cur_title, &mut cur_rationale, &mut cur_condition, &mut cur_rules);
    }

    /// Run compliance assessment against the Linux host and return `(passed, total, score_pct)`.
    pub async fn run_sca_assessment(&self, buffer: &AgentBuffer) -> (usize, usize, usize) {
        let mut passed_count = 0;
        let mut failed_count = 0;

        for check in &self.checks {
            let passed = self.evaluate_check(check);
            if passed {
                passed_count += 1;
            } else {
                failed_count += 1;
            }

            let status_str = if passed { "PASSED" } else { "FAILED" };
            let log_msg = format!(
                "provigil-sca: [{}] CIS Check #{}: '{}' on {}",
                status_str, check.id, check.title, check.target_file
            );

            let mut event = RawEvent::new(&self.agent_id, EventSource::Sca, "sca/cis-linux", log_msg);
            event.metadata.insert("check_id".into(), check.id.to_string());
            event.metadata.insert("title".into(), check.title.clone());
            event.metadata.insert("target_file".into(), check.target_file.clone());
            event.metadata.insert("status".into(), status_str.to_lowercase());
            event.metadata.insert("rationale".into(), check.rationale.clone());
            event.metadata.insert("os_type".into(), "linux".into());

            buffer.push(event).await;
        }

        let total = passed_count + failed_count;
        let score_pct = if total > 0 { (passed_count * 100) / total } else { 0 };
        info!(
            "provigil-sca: Completed Linux CIS Assessment. Passed: {}/{}, Score: {}%",
            passed_count, total, score_pct
        );
        (passed_count, total, score_pct)
    }

    fn evaluate_check(&self, check: &LinuxScaCheck) -> bool {
        match &check.rule_type {
            ScaRuleType::FilePermissions { max_octal } => {
                let p = Path::new(&check.target_file);
                if !p.exists() {
                    return false;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = p.metadata() {
                        let mode = meta.permissions().mode() & 0o7777;
                        return (mode & !max_octal) == 0;
                    }
                    return false;
                }
                #[cfg(not(unix))]
                {
                    let _ = max_octal;
                    true
                }
            }
            ScaRuleType::ConfigFileEntry { key, expected } => {
                let p = Path::new(&check.target_file);
                let Ok(file) = File::open(p) else {
                    return false;
                };
                let reader = BufReader::new(file);
                let key_lc = key.to_lowercase();
                let exp_lc = expected.to_lowercase();
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') || trimmed.is_empty() {
                        continue;
                    }
                    let line_lc = trimmed.to_lowercase();
                    if line_lc.contains(&key_lc) && line_lc.contains(&exp_lc) {
                        return true;
                    }
                }
                false
            }
            ScaRuleType::SysctlParam { path, expected } => {
                let p = Path::new(path);
                match std::fs::read_to_string(p) {
                    Ok(content) => content.trim() == expected,
                    Err(_) => false,
                }
            }
            ScaRuleType::YamlRules { condition, rules } => {
                evaluate_yaml_rules(*condition, rules)
            }
        }
    }
}

fn unquote_yaml(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn extract_rule_target(rule: &str) -> Option<String> {
    let trimmed = rule.trim().trim_start_matches('!');
    if let Some(rest) = trimmed.strip_prefix("f:").or_else(|| trimmed.strip_prefix("d:")) {
        return Some(rest.split("->").next()?.trim().to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("c:") {
        return Some(rest.split("->").next()?.trim().to_string());
    }
    None
}

fn evaluate_yaml_rules(condition: ScaCondition, rules: &[String]) -> bool {
    if rules.is_empty() {
        return false;
    }
    let mut results = rules.iter().map(|r| evaluate_single_rule(r));
    match condition {
        ScaCondition::All => results.all(|v| v),
        ScaCondition::Any => results.any(|v| v),
        ScaCondition::None => results.all(|v| !v),
    }
}

fn evaluate_single_rule(rule: &str) -> bool {
    let (negated_prefix, expr) = match rule.trim().strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, rule.trim()),
    };

    let (lhs, rhs) = match expr.split_once("->") {
        Some((l, r)) => (l.trim(), Some(r.trim())),
        None => (expr, None),
    };

    let raw_ok = if let Some(path) = lhs.strip_prefix("f:") {
        let p = Path::new(path.trim());
        match rhs {
            None => p.is_file(),
            Some(matcher) => match std::fs::read_to_string(p) {
                Ok(content) => match_text(&content, matcher),
                Err(_) => false,
            },
        }
    } else if let Some(path) = lhs.strip_prefix("d:") {
        Path::new(path.trim()).is_dir()
    } else if let Some(cmd) = lhs.strip_prefix("c:") {
        let out = Command::new("sh").args(["-c", cmd.trim()]).output();
        match out {
            Ok(o) => {
                let text = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                match rhs {
                    Some(matcher) => match_text(&text, matcher),
                    None => o.status.success(),
                }
            }
            Err(_) => false,
        }
    } else if let Some(proc_name) = lhs.strip_prefix("p:") {
        let target = proc_name.trim();
        let mut found = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                        if comm.trim() == target {
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        found
    } else {
        false
    };

    if negated_prefix { !raw_ok } else { raw_ok }
}

fn match_text(content: &str, matcher: &str) -> bool {
    for part in matcher.split("&&") {
        let part = part.trim();
        if !match_clause(content, part) {
            return false;
        }
    }
    true
}

fn match_clause(content: &str, clause: &str) -> bool {
    let (neg, pat) = match clause.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, clause.trim()),
    };

    let matched = if let Some(rx) = pat.strip_prefix("r:") {
        content.lines().any(|line| simple_pattern_match(line, rx.trim()))
            || simple_pattern_match(content, rx.trim())
    } else if let Some(num) = pat.strip_prefix("n:") {
        content.contains(num.trim())
    } else {
        content.contains(pat)
    };

    if neg { !matched } else { matched }
}

fn simple_pattern_match(haystack: &str, pattern: &str) -> bool {
    for alt in pattern.split('|') {
        let mut pat = alt.trim();
        let anchored_start = pat.starts_with('^');
        let anchored_end = pat.ends_with('$');
        pat = pat.trim_start_matches('^').trim_end_matches('$');
        // Strip common regex escapes and whitespace quantifiers for practical substring matching
        let cleaned = pat
            .replace("\\s+", " ")
            .replace("\\s*", " ")
            .replace("\\s", " ")
            .replace("\\.", ".");
        let tokens: Vec<&str> = cleaned.split_whitespace().filter(|t| !t.is_empty()).collect();
        if tokens.is_empty() {
            return true;
        }
        if anchored_start && anchored_end && tokens.len() == 1 {
            if haystack.trim() == tokens[0] {
                return true;
            }
        } else if anchored_start && tokens.len() == 1 {
            if haystack.trim_start().starts_with(tokens[0]) {
                return true;
            }
        } else {
            let mut pos = 0;
            let mut ok = true;
            for tok in &tokens {
                if let Some(idx) = haystack[pos..].find(tok) {
                    pos += idx + tok.len();
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                return true;
            }
        }
    }
    false
}

/// Spawns the Linux SCA worker running periodic CIS benchmark assessments.
pub fn spawn_sca_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine = LinuxScaEngine::new(agent_id);

        loop {
            tokio::time::sleep(interval).await;
            if lifecycle.is_terminated() {
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }
            engine.run_sca_assessment(&buffer).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_evaluates_real_cis_yaml_rules() {
        let dir = std::env::temp_dir().join(format!("provigil_sca_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("sshd_config");
        std::fs::write(&target, "PermitRootLogin no\nProtocol 2\n").unwrap();

        let yaml = dir.join("policy.yml");
        std::fs::write(
            &yaml,
            format!(
                "policy:\n  id: test\nchecks:\n  - id: 9001\n    title: \"SSH Root Login\"\n    condition: all\n    rules:\n      - \"f:{} -> r:PermitRootLogin no\"\n      - \"!f:{}\"\n  - id: 9002\n    title: \"Fail on missing\"\n    condition: all\n    rules:\n      - \"f:{} -> r:PasswordAuthentication no\"\n",
                target.display(),
                dir.join("missing.conf").display(),
                target.display(),
            ),
        )
        .unwrap();

        let mut checks = Vec::new();
        LinuxScaEngine::parse_cis_yaml(&yaml, &mut checks);
        assert_eq!(checks.len(), 2);

        let engine = LinuxScaEngine {
            agent_id: "001".into(),
            checks,
        };
        assert!(engine.evaluate_check(&engine.checks[0]));
        assert!(!engine.evaluate_check(&engine.checks[1]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
