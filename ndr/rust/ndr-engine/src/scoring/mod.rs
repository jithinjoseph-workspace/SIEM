// NDR Engine — Risk Scoring Engine
// Scoring rules inspired by Malcolm's 23_severity.conf (public domain, CC0).
// All weights and logic freshly designed — zero code copied. License: Apache-2.0

use crate::correlator::CorrelationHit;
use serde::{Deserialize, Serialize};

// ── Severity levels ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical, // 80–100
    High,     // 60–79
    Medium,   // 40–59
    Low,      // 20–39
    Info,     //  0–19
}

impl Severity {
    /// Score using default thresholds (backward compatible).
    pub fn from_score(score: f32) -> Self {
        Self::from_score_with_thresholds(score, 90, 75, 50, 25)
    }

    /// Score using configurable thresholds from settings.
    pub fn from_score_with_thresholds(
        score: f32, critical: u32, high: u32, medium: u32, low: u32
    ) -> Self {
        let s = score as u32;
        if s >= critical { Severity::Critical }
        else if s >= high { Severity::High }
        else if s >= medium { Severity::Medium }
        else if s >= low { Severity::Low }
        else { Severity::Info }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }

    pub fn colour(&self) -> &'static str {
        match self {
            Severity::Critical => "#ff4444",
            Severity::High     => "#ff8800",
            Severity::Medium   => "#ffcc00",
            Severity::Low      => "#44aaff",
            Severity::Info     => "#888888",
        }
    }
}

// ── Risk result ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskResult {
    pub score:    f32,
    pub severity: Severity,
    pub tags:     Vec<String>,
    pub reasons:  Vec<String>,
}

// ── conn_state descriptions ───────────────────────────────────────────────
// Reference: https://docs.zeek.org/en/stable/logs/conn.html

pub fn conn_state_description(state: &str) -> &'static str {
    match state {
        "S0"     => "Connection attempt, no reply",
        "S1"     => "Connection established, not terminated",
        "S2"     => "Connection established, originator silent",
        "S3"     => "Connection established, responder silent",
        "SF"     => "Normal establishment and termination",
        "REJ"    => "Connection attempt rejected",
        "RSTO"   => "Connection reset by originator",
        "RSTR"   => "Connection reset by responder",
        "RSTOS0" => "SYN then RST from originator, no SYN-ACK seen",
        "RSTRH"  => "SYN-ACK then RST from responder, no SYN seen",
        "SH"     => "Originator SYN + FIN, no SYN-ACK (half-open scan)",
        "SHR"    => "Responder SYN-ACK + FIN, no SYN",
        "OTH"    => "Mid-stream traffic, no SYN seen",
        _        => "Unknown state",
    }
}

// ── Scorer ────────────────────────────────────────────────────────────────

pub struct RiskScorer;

impl RiskScorer {
    pub fn new() -> Self { RiskScorer }

    /// Score a correlated pair.
    ///
    /// `is_malicious`      — src or dst IP matched threat intel feed
    /// `sensitive_country` — src or dst GeoIP country in the sensitive list
    /// `is_trusted_cloud`  — dst ASN is a known cloud provider (from TrustedRanges, DB-driven)
    pub fn score(
        &self,
        hit: &CorrelationHit,
        is_malicious: bool,
        sensitive_country: bool,
        is_trusted_cloud: bool,
        entity_score: f32,
    ) -> RiskResult {
        let mut score: f32 = 0.0;
        let mut tags       = Vec::<String>::new();
        let mut reasons    = Vec::<String>::new();

        let zeek     = &hit.agent_z;
        let suricata = &hit.agent_s;

        // ── 1. Threat intel (highest signal) ─────────────────────────
        if is_malicious {
            score += 80.0;
            reasons.push("IP matches threat intel feed (abuse.ch)".into());
            tags.push("threat-intel".into());
        }

        // ── 2. Suricata alert ─────────────────────────────────────────
        if suricata.event_type.as_deref() == Some("alert") {
            let is_suricata_internal = suricata.alert.as_ref()
                .map(|a| a.signature.starts_with("SURICATA "))
                .unwrap_or(false);

            if is_suricata_internal {
                // Internal Suricata engine diagnostics (protocol anomalies, stream
                // quirks) — not real threat detections. Tag but do not boost score.
                tags.push("agent-s-internal".into());
                if let Some(alert) = &suricata.alert {
                    reasons.push(format!("Agent-S internal diagnostic: {}", alert.signature));
                }
            } else {
                tags.push("ids-alert".into());

                if let Some(alert) = &suricata.alert {
                    // Suricata severity: 1=high, 2=medium, 3=low
                    // Sev-3 gets 20pts — needs a second signal (sensitive country, threat intel,
                    // sigma) to reach hit threshold; prevents sev-3-only CDN noise from flooding
                    match alert.severity {
                        1 => { score += 90.0; reasons.push("Agent-S HIGH severity alert".into()); tags.push("alert-sev-high".into()); }
                        2 => { score += 75.0; reasons.push("Agent-S MEDIUM severity alert".into()); tags.push("alert-sev-medium".into()); }
                        _ => { score += 20.0; tags.push("alert-sev-low".into()); }
                    }
                    if !alert.signature.is_empty() {
                        reasons.push(format!("Rule: {}", alert.signature));
                    }
                    for t in &alert.mitre_tactics {
                        score += 10.0;
                        tags.push(format!("mitre:{}", t));
                    }
                    for t in &alert.mitre_techniques {
                        tags.push(format!("technique:{}", t));
                    }
                }
            }
        }

        // ── 3. Sensitive country GeoIP ────────────────────────────────
        // Skip if dst is a trusted cloud provider — major clouds (Azure, Google,
        // Amazon) have PoPs in every country including sensitive ones. Traffic to
        // AS8075 in India is Windows Update, not a geo threat signal.
        if sensitive_country && !is_trusted_cloud {
            score += 30.0;
            reasons.push("Traffic involves a sensitive country".into());
            tags.push("sensitive-country".into());
        }

        // ── 4. Zeek conn_state analysis ───────────────────────────────
        if let Some(cs) = &zeek.conn_state {
            match cs.as_str() {
                "REJ" => {
                    // Single rejection is normal (closed port). Needs correlation to alert.
                    score += 8.0;
                    reasons.push("Connection rejected — possible port scan".into());
                    tags.push("port-scan".into());
                }
                "RSTO" | "RSTR" => {
                    // Resets are constant in normal traffic — don't alert in isolation.
                    score += 5.0;
                    reasons.push("Connection reset".into());
                    tags.push("connection-reset".into());
                }
                "RSTOS0" | "RSTRH" => {
                    // Abnormal RST sequence — genuinely suspicious, keep higher.
                    score += 12.0;
                    reasons.push("Abnormal RST — likely scan or spoofing".into());
                    tags.push("abnormal-rst".into());
                }
                "S0" => {
                    // SYN no reply — common for any offline host or UDP port.
                    score += 4.0;
                    reasons.push("SYN with no reply".into());
                    tags.push("no-response".into());
                }
                "SH" | "SHR" => {
                    // Half-open — normal for DNS/NTP/UDP protocols.
                    score += 5.0;
                    reasons.push("Half-open connection".into());
                    tags.push("half-open".into());
                }
                "SF" | "S1" => { tags.push("normal-flow".into()); }
                "OTH"       => { score += 5.0; tags.push("mid-stream".into()); }
                _           => {}
            }
        }

        // ── 5. Destination port ───────────────────────────────────────
        let dst_port = suricata.dest_port.or(zeek.dest_port).unwrap_or(0);
        match dst_port {
            22   => { tags.push("ssh".into()); }
            23   => {
                score += 20.0;
                tags.push("telnet".into());
                reasons.push("Telnet — unencrypted remote access".into());
            }
            445  => {
                score += 15.0;
                tags.push("smb".into());
                reasons.push("SMB — common lateral movement target".into());
            }
            3389 => {
                score += 15.0;
                tags.push("rdp".into());
                reasons.push("RDP — common ransomware entry point".into());
            }
            4444 | 5555 | 1337 | 9001 | 8888 => {
                score += 25.0;
                tags.push("suspicious-port".into());
                reasons.push(format!("Port {} — common C2/malware port", dst_port));
            }
            _ => {}
        }

        // ── 6. Insecure protocol (from Malcolm's severity logic) ──────
        if let Some(svc) = &zeek.network_protocol {
            match svc.as_str() {
                "ftp" | "telnet" | "rlogin" | "rsh" => {
                    score += 15.0;
                    reasons.push(format!("Insecure protocol: {}", svc));
                    tags.push("insecure-protocol".into());
                }
                other if !other.is_empty() => {
                    tags.push(format!("protocol:{}", other));
                }
                _ => {}
            }
        }

        // ── 7. Trusted cloud provider — suppress behavioral noise ─────
        // Caller resolves trust via TrustedRanges (DB-driven keywords, no hardcoding).
        // Cap score only when there is no real threat signal.
        if is_trusted_cloud {
            let has_real_signal = is_malicious
                || tags.contains(&"beaconing".to_string()) // beacon hits bypass trusted-cloud cap
                || (suricata.event_type.as_deref() == Some("alert")
                    && !suricata.alert.as_ref()
                        .map(|a| a.signature.starts_with("SURICATA "))
                        .unwrap_or(false));
            if !has_real_signal {
                score = score.min(8.0);
                tags.push("trusted-cloud".into());
                reasons.push(
                    "Destination is trusted cloud provider — behavioral noise suppressed".into()
                );
            }
        }

        // ── 8. Entity score (per-host accumulated risk from last 24 h) ──────
        // entity_score is the host's accumulated hit score normalized to 0-100.
        // A history of repeated suspicious activity boosts new hits from that host.
        if entity_score >= 80.0 {
            score += 20.0;
            reasons.push(format!("Compromised-host history (entity score {:.0})", entity_score));
            tags.push("compromised-host".into());
        } else if entity_score >= 50.0 {
            score += 10.0;
            reasons.push(format!("Risky host (entity score {:.0})", entity_score));
            tags.push("risky-host".into());
        } else if entity_score >= 30.0 {
            score += 5.0;
            tags.push("flagged-host".into());
        }

        score = score.min(100.0);
        let severity = Severity::from_score(score);

        RiskResult { score, severity, tags, reasons }
    }
}
