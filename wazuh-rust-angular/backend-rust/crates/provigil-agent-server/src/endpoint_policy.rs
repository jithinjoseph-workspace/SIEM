//! Endpoint control policies (specs/compliance-and-endpoint-policy.md, part B): a tenant's own
//! site and application rules, enforced on its agents. siem-api stores and checks them and raises
//! the attempt alerts; the gateway adds each agent's rules to its group settings
//! (`endpoint_policies`); the agent applies them.
//!
//! Kinds:
//! - `site`: domains (each covers its sub-domains; `*.` in front is accepted and dropped);
//! - `app`: program file names (`chatgpt.exe`) or `sha256:<hex>`;
//! - `safe_search`: browsers forced to safe search (Google, Bing, YouTube restricted), no targets.
//!
//! Mode `monitor` alerts only; `enforce` blocks and alerts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const KINDS: [&str; 3] = ["site", "app", "safe_search"];
pub const MAX_RULES: usize = 200;
pub const MAX_TARGETS: usize = 5000;
pub const MAX_MESSAGE: usize = 300;

/// Programs a rule may never stop: the OS, shells and installers ProVigil itself runs, and ProVigil.
/// (The agent keeps the same list and refuses them again.)
pub const PROTECTED_APPS: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "conhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "runtimebroker.exe", "spoolsv.exe", "fontdrvhost.exe", "logonui.exe", "userinit.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "sc.exe", "reg.exe", "wevtutil.exe", "auditpol.exe", "secedit.exe", "netsh.exe",
    "provigil-agent.exe", "provigil-blocked.exe", "tamper-protect.exe", "restart-agent.exe", "isolate-host.exe", "sysmon.exe", "sysmon64.exe",
    "init", "systemd", "sshd", "sh", "bash", "dash", "sudo", "su", "login", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "zypper", "provigil-agent", "siem-agent-linux",
];

/// One rule as stored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub targets: Vec<String>,
    /// manager group names (`<tenant>.<group>`, or `default`); empty: every agent of the tenant
    #[serde(default)]
    pub groups: Vec<String>,
    /// `any`, `windows` or `linux`
    #[serde(default)]
    pub os: String,
    /// shown to the person when blocked
    #[serde(default)]
    pub message: String,
    /// sites: also the browsers' own block list (covers every sub-domain and path, but the browser
    /// then blocks before looking the name up, so browser attempts raise no alert)
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: u64,
}

/// A domain as rules keep it: lower case, no scheme, path, port or leading `*.` / `www.`.
pub fn domain(t: &str) -> Result<String, String> {
    let mut d = t.trim().to_ascii_lowercase();
    for p in ["https://", "http://"] {
        if let Some(r) = d.strip_prefix(p) {
            d = r.to_string();
        }
    }
    d = d.split(['/', '?', '#']).next().unwrap_or("").to_string();
    d = d.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h.to_string()).unwrap_or(d);
    let d = d.trim_start_matches("*.").trim_start_matches("www.").trim_end_matches('.').to_string();
    let labels: Vec<&str> = d.split('.').collect();
    if d.len() > 253 || labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) {
        return Err(format!("'{}' is not a domain name (e.g. chatgpt.com)", t.trim()));
    }
    // a whole top-level domain, or an address
    if labels.last().is_some_and(|l| l.chars().all(|c| c.is_ascii_digit())) {
        return Err(format!("'{}': give a domain name, not an address", t.trim()));
    }
    // shortcut: two-label public suffixes (co.uk, com.om...) are refused by this short list only; a full public suffix list if tenants hit others
    if labels.len() == 2 && ["co", "com", "net", "org", "gov", "edu", "ac"].contains(&labels[0]) {
        return Err(format!("'{}' is a whole country domain: too wide", t.trim()));
    }
    if d == "localhost" || d.ends_with(".local") || d.ends_with(".localhost") {
        return Err(format!("'{}' is a local name", t.trim()));
    }
    Ok(d)
}

/// An application target as rules keep it: a file name in lower case, or `sha256:<hex>`.
pub fn app(t: &str) -> Result<String, String> {
    let s = t.trim().to_ascii_lowercase();
    if let Some(h) = s.strip_prefix("sha256:") {
        let h = h.trim();
        return if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) { Ok(format!("sha256:{h}")) } else { Err(format!("'{}': a SHA-256 has 64 hex characters", t.trim())) };
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(format!("sha256:{s}"));
    }
    if s.is_empty() || s.len() > 100 || s.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) || s.starts_with('.') {
        return Err(format!("'{}': give the program's file name (e.g. chatgpt.exe) or its SHA-256", t.trim()));
    }
    if PROTECTED_APPS.contains(&s.as_str()) {
        return Err(format!("'{s}' is a system or ProVigil program: blocking it would break the computer or ProVigil"));
    }
    Ok(s)
}

impl Rule {
    /// Cleans the rule (names, targets in their kept form, no repeats); Err: the message for the person.
    pub fn validate(mut self) -> Result<Rule, String> {
        self.name = self.name.trim().chars().filter(|c| !c.is_control()).take(80).collect();
        if self.name.is_empty() {
            return Err("Give the rule a name".into());
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Err("The rule is for sites, applications or safe search".into());
        }
        if !["monitor", "enforce"].contains(&self.mode.as_str()) {
            return Err("The mode is monitor (alert only) or enforce (block and alert)".into());
        }
        if self.os.is_empty() {
            self.os = "any".into();
        }
        if !["any", "windows", "linux"].contains(&self.os.as_str()) {
            return Err("The operating system is any, windows or linux".into());
        }
        // plain text only: shown in a system dialog
        self.message = self.message.chars().filter(|c| !c.is_control() && !matches!(c, '<' | '>')).take(MAX_MESSAGE).collect::<String>().trim().to_string();
        let clean: Result<Vec<String>, String> = match self.kind.as_str() {
            "site" => self.targets.iter().filter(|t| !t.trim().is_empty()).map(|t| domain(t)).collect(),
            "app" => self.targets.iter().filter(|t| !t.trim().is_empty()).map(|t| app(t)).collect(),
            _ => Ok(Vec::new()),
        };
        let mut targets = clean?;
        targets.sort();
        targets.dedup();
        if self.kind != "safe_search" && targets.is_empty() {
            return Err(if self.kind == "site" { "Add at least one site".into() } else { "Add at least one program".into() });
        }
        if targets.len() > MAX_TARGETS {
            return Err(format!("At most {MAX_TARGETS} entries per rule"));
        }
        self.targets = targets;
        self.strict &= self.kind == "site";
        self.groups.sort();
        self.groups.dedup();
        Ok(self)
    }

    /// Whether the rule is for an agent in these manager groups, of this OS.
    pub fn applies(&self, agent_groups: &[String], os_type: &str) -> bool {
        let os_ok = self.os == "any" || self.os.is_empty() || os_type.is_empty() || self.os.eq_ignore_ascii_case(os_type);
        self.enabled && os_ok && (self.groups.is_empty() || self.groups.iter().any(|g| agent_groups.contains(g)))
    }

    /// The form the agent gets.
    pub fn for_agent(&self) -> Value {
        json!({ "id": self.id, "kind": self.kind, "mode": self.mode, "targets": self.targets, "message": self.message, "strict": self.strict })
    }

    /// The target of a site rule a looked-up name falls under.
    pub fn site_hit(&self, name: &str) -> Option<&str> {
        let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
        self.targets.iter().find(|d| n == **d || n.strip_suffix(d.as_str()).is_some_and(|p| p.ends_with('.'))).map(String::as_str)
    }

    /// The target of an app rule a started program falls under (its full path, its SHA-256 if known).
    pub fn app_hit(&self, image: &str, sha256: &str) -> Option<&str> {
        let file = image.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
        let h = sha256.trim().to_ascii_lowercase();
        self.targets.iter().find(|t| match t.strip_prefix("sha256:") {
            Some(x) => !h.is_empty() && x == h,
            None => !file.is_empty() && **t == file,
        }).map(String::as_str)
    }
}

/// The rules for one agent, in the agent's form (rules stay in their stored order).
pub fn for_agent(rules: &[Rule], agent_groups: &[String], os_type: &str) -> Vec<Value> {
    rules.iter().filter(|r| r.applies(agent_groups, os_type)).map(Rule::for_agent).collect()
}

/// Ready-made rules the page offers (the tenant can edit them before saving).
pub fn presets() -> Value {
    json!([
        { "name": "Generative AI websites", "kind": "site", "mode": "monitor",
          "targets": ["chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com", "perplexity.ai", "poe.com", "chat.deepseek.com", "character.ai", "you.com"],
          "message": "Generative AI sites are not allowed by your organisation's policy." },
        { "name": "Generative AI desktop apps", "kind": "app", "mode": "monitor",
          "targets": ["chatgpt.exe", "claude.exe"],
          "message": "This application is not allowed by your organisation's policy." },
        { "name": "Safe search in browsers", "kind": "safe_search", "mode": "enforce", "targets": [],
          "message": "" },
        { "name": "Adult content (paste your list)", "kind": "site", "mode": "monitor", "targets": [],
          "message": "This site is blocked by your organisation's policy.",
          "note": "Paste or upload a list of adult sites (one per line). ProVigil does not ship such a list; for whole categories a filtering DNS service is planned." }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: &str, targets: &[&str]) -> Rule {
        Rule { name: "r".into(), kind: kind.into(), mode: "enforce".into(), targets: targets.iter().map(|s| s.to_string()).collect(), enabled: true, ..Default::default() }
    }

    #[test]
    fn domains_are_kept_plain_and_wide_ones_refused() {
        assert_eq!(domain("https://www.ChatGPT.com/c/123").unwrap(), "chatgpt.com");
        assert_eq!(domain("*.openai.com").unwrap(), "openai.com");
        assert_eq!(domain("chat.openai.com:443").unwrap(), "chat.openai.com");
        for bad in ["com", "*.com", "*", "co.uk", "10.0.0.1", "localhost", "printer.local", "bad_name.com", "-x.com"] {
            assert!(domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn apps_by_name_or_hash_never_system_ones() {
        assert_eq!(app("ChatGPT.exe").unwrap(), "chatgpt.exe");
        let h = "A".repeat(64);
        assert_eq!(app(&h).unwrap(), format!("sha256:{}", "a".repeat(64)));
        assert!(app("sha256:abc").is_err());
        for bad in ["explorer.exe", "svchost.exe", "powershell.exe", "provigil-agent.exe", "systemd", "C:\\x\\a.exe", ""] {
            assert!(app(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn validate_cleans_and_refuses() {
        let r = Rule { message: "No <b>AI</b>\n".into(), ..rule("site", &["www.chatgpt.com", "chatgpt.com", " "]) }.validate().unwrap();
        assert_eq!(r.targets, vec!["chatgpt.com"]);
        assert_eq!(r.message, "No bAI/b");
        assert_eq!(r.os, "any");
        assert!(rule("site", &[]).validate().is_err(), "no site");
        assert!(Rule { mode: "block".into(), ..rule("site", &["a.com"]) }.validate().is_err());
        assert!(rule("safe_search", &[]).validate().is_ok());
        assert!(!Rule { strict: true, ..rule("app", &["x.exe"]) }.validate().unwrap().strict, "strict is for sites");
    }

    #[test]
    fn scope_and_matching() {
        let r = Rule { groups: vec!["acm.office".into()], os: "windows".into(), ..rule("site", &["chatgpt.com"]) };
        assert!(r.applies(&["acm.office".into()], "windows"));
        assert!(!r.applies(&["acm.lab".into()], "windows"));
        assert!(!r.applies(&["acm.office".into()], "linux"));
        assert!(!Rule { enabled: false, ..r.clone() }.applies(&["acm.office".into()], "windows"));
        assert_eq!(r.site_hit("cdn.chatgpt.com."), Some("chatgpt.com"));
        assert_eq!(r.site_hit("notchatgpt.com"), None);
        let a = rule("app", &["chatgpt.exe", &format!("sha256:{}", "b".repeat(64))]);
        assert_eq!(a.app_hit("C:\\Users\\x\\AppData\\Local\\ChatGPT.exe", ""), Some("chatgpt.exe"));
        assert!(a.app_hit("C:\\renamed.exe", &"B".repeat(64)).is_some(), "by hash when renamed");
        assert_eq!(a.app_hit("C:\\other.exe", ""), None);
        assert_eq!(for_agent(&[r], &["acm.office".into()], "windows")[0]["targets"][0], "chatgpt.com");
    }
}
