//! Alert suppressions for the SIEM: hide one noisy Wazuh rule for one agent
//! and/or one source IP, for a limited time. They come from a triage
//! recommendation a person applied, or from an analyst directly; nothing
//! suppresses on its own.
//!
//! Safety rules, whoever created the suppression:
//! - it names a rule, a source IP or both, so it can never hide everything;
//! - it always expires (1 hour to 7 days);
//! - critical alerts (level >= [`NEVER_HIDE_LEVEL`]) are never hidden.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const NEVER_HIDE_LEVEL: u32 = 12;
pub const MIN_HOURS: u32 = 1;
pub const MAX_HOURS: u32 = 168;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suppression {
    pub id: String,
    /// `None` = any rule (then `src_ip` is required).
    pub rule_id: Option<u32>,
    /// The rule's description, for display.
    pub rule_name: String,
    /// `None` = any agent.
    pub agent_id: Option<String>,
    pub agent_name: String,
    /// `None` = any source.
    pub src_ip: Option<String>,
    pub reason: String,
    /// "triage" (a recommendation a person applied) or "manual".
    pub source: String,
    /// The triage verdict's confidence (100 for manual ones).
    pub confidence: u8,
    pub created_by: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub active: bool,
}

/// The fields of an alert a suppression looks at.
#[derive(Debug, Clone, Default)]
pub struct AlertKey<'a> {
    pub rule_id: u32,
    pub level: u32,
    pub agent_id: &'a str,
    pub src_ip: &'a str,
}

/// What a person asks for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub rule_id: Option<u32>,
    #[serde(default)]
    pub rule_name: String,
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: String,
    pub src_ip: Option<String>,
    pub hours: Option<u32>,
    #[serde(default)]
    pub reason: String,
}

impl Suppression {
    /// Checks and builds one: a rule or a source is required, the source must be an
    /// IP address, the duration is clamped to 1 h .. 7 days.
    pub fn new(id: String, r: Request, source: &str, confidence: u8, created_by: &str, now: u64) -> Result<Suppression, String> {
        let src_ip = r.src_ip.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let agent_id = r.agent_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if r.rule_id.is_none() && src_ip.is_none() {
            return Err("A suppression needs a rule, a source IP or both".into());
        }
        if let Some(ip) = &src_ip {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("'{ip}' is not an IP address"));
            }
        }
        let hours = r.hours.unwrap_or(24).clamp(MIN_HOURS, MAX_HOURS);
        let reason: String = if r.reason.trim().is_empty() { format!("Suppressed by {created_by} for {hours}h") } else { r.reason.trim().to_string() };
        Ok(Suppression {
            id,
            rule_id: r.rule_id,
            rule_name: r.rule_name.chars().take(200).collect(),
            agent_id,
            agent_name: r.agent_name.chars().take(100).collect(),
            src_ip,
            reason: reason.chars().take(400).collect(),
            source: source.into(),
            confidence,
            created_by: created_by.into(),
            created_at: now,
            expires_at: now + hours as u64 * 3600,
            active: true,
        })
    }

    pub fn in_force(&self, now: u64) -> bool {
        self.active && now < self.expires_at
    }

    pub fn matches(&self, a: &AlertKey, now: u64) -> bool {
        self.in_force(now)
            && a.level < NEVER_HIDE_LEVEL
            && self.rule_id.map_or(true, |r| r == a.rule_id)
            && self.agent_id.as_deref().map_or(true, |g| g == a.agent_id)
            && self.src_ip.as_deref().map_or(true, |s| s == a.src_ip)
    }

    /// A row of the AI activity page.
    pub fn view(&self, now: u64) -> Value {
        json!({
            "id": self.id,
            "active": self.in_force(now),
            "signature_id": self.rule_id.map(|r| r.to_string()).unwrap_or_else(|| "any".into()),
            "signature_name": if self.rule_name.is_empty() { self.rule_id.map(|r| format!("Rule {r}")).unwrap_or_else(|| "Any rule".into()) } else { self.rule_name.clone() },
            "suppress_type": match (&self.agent_id, &self.src_ip) {
                (Some(_), Some(_)) => "by_agent_and_src",
                (Some(_), None) => "by_agent",
                (None, Some(_)) => "by_src",
                (None, None) => "by_rule",
            },
            "suppress_scope": "group",
            "suppress_ip": self.src_ip.clone().unwrap_or_default(),
            "src_ip": self.src_ip.clone().unwrap_or_default(),
            "dst_ip": if self.agent_name.is_empty() { self.agent_id.clone().unwrap_or_default() } else { self.agent_name.clone() },
            "community_id": "",
            "ai_reason": self.reason,
            "ai_confidence": self.confidence,
            "source": self.source,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        })
    }
}

/// The first suppression that hides this alert.
pub fn find<'a>(list: &'a [Suppression], a: &AlertKey, now: u64) -> Option<&'a Suppression> {
    list.iter().find(|s| s.matches(a, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(rule: Option<u32>, agent: Option<&str>, src: Option<&str>, hours: Option<u32>) -> Request {
        Request { rule_id: rule, agent_id: agent.map(String::from), src_ip: src.map(String::from), hours, ..Default::default() }
    }

    #[test]
    fn needs_a_rule_or_a_source() {
        assert!(Suppression::new("1".into(), req(None, Some("001"), None, None), "manual", 100, "ana", 0).is_err());
        assert!(Suppression::new("1".into(), req(None, None, Some("not-an-ip"), None), "manual", 100, "ana", 0).is_err());
        assert!(Suppression::new("1".into(), req(Some(5710), None, None, None), "manual", 100, "ana", 0).is_ok());
    }

    #[test]
    fn matching_scope_expiry_and_critical() {
        let s = Suppression::new("1".into(), req(Some(5710), Some("001"), None, Some(2)), "triage", 85, "ana", 1000).unwrap();
        let a = |rule, level, agent| AlertKey { rule_id: rule, level, agent_id: agent, src_ip: "1.2.3.4" };
        assert!(s.matches(&a(5710, 5, "001"), 1000));
        assert!(!s.matches(&a(5710, 5, "002"), 1000), "other agent");
        assert!(!s.matches(&a(5711, 5, "001"), 1000), "other rule");
        assert!(!s.matches(&a(5710, 12, "001"), 1000), "critical alerts are never hidden");
        assert!(!s.matches(&a(5710, 5, "001"), 1000 + 2 * 3600), "expired");
        let mut off = s.clone();
        off.active = false;
        assert!(!off.matches(&a(5710, 5, "001"), 1000));
        // clamped to 7 days
        let long = Suppression::new("2".into(), req(Some(1), None, None, Some(10_000)), "manual", 100, "ana", 0).unwrap();
        assert_eq!(long.expires_at, MAX_HOURS as u64 * 3600);
        assert_eq!(s.view(1000)["suppress_type"], "by_agent");
    }
}
