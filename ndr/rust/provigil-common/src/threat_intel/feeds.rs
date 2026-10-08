//! Pure feed parsers — take an already-fetched HTTP response body and return
//! a list of [`ThreatIntelEntry`] values ready to store.
//!
//! No network calls here.  The engine (ndr-engine / siem-engine) does:
//!   1. HTTP GET  →  raw text / JSON
//!   2. parse_*(…) from this module
//!   3. Insert the returned Vec<ThreatIntelEntry> into its own storage
//!
//! This keeps the parsing logic in one place and lets every engine stay in sync
//! automatically when feeds change their format.

use super::ThreatIntelEntry;
use chrono::Duration;

// ── CISA Known Exploited Vulnerabilities ─────────────────────────────────────

/// Parse the CISA KEV JSON feed.
/// Only returns vulnerabilities added in the last 90 days to keep the table lean.
pub fn parse_cisa_kev(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let vulns = match data["vulnerabilities"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let cutoff = (chrono::Utc::now() - Duration::days(90)).date_naive();
    let mut out = Vec::new();

    for v in vulns.iter().take(200) {
        let date_added = v["dateAdded"].as_str().unwrap_or("");
        if let Ok(added) = chrono::NaiveDate::parse_from_str(date_added, "%Y-%m-%d") {
            if added < cutoff { continue; }
        }

        let cve        = v["cveID"].as_str().unwrap_or("");
        let vendor     = v["vendorProject"].as_str().unwrap_or("");
        let product    = v["product"].as_str().unwrap_or("");
        let vuln_name  = v["vulnerabilityName"].as_str().unwrap_or("");
        let short_desc = v["shortDescription"].as_str().unwrap_or("");
        let action     = v["requiredAction"].as_str().unwrap_or("");
        let due_date   = v["dueDate"].as_str().unwrap_or("");
        let ransomware = v["knownRansomwareCampaignUse"].as_str().unwrap_or("Unknown");

        let attack_type = classify_attack(short_desc, cve);
        let severity    = if ransomware == "Known" { "CRITICAL" } else { "HIGH" };
        let description = format!("{} {} — {}", vendor, product, short_desc);
        let threat_pattern = format!(
            "{} affects {} {}. Vulnerability: {}. {}{}Action required: {}. Patch by: {}.",
            cve, vendor, product, vuln_name,
            if ransomware == "Known" { "ACTIVE RANSOMWARE CAMPAIGN USE. " } else { "" },
            if !short_desc.is_empty() { format!("Attack: {}. ", short_desc) } else { String::new() },
            action, due_date
        );

        out.push(ThreatIntelEntry {
            source: "cisa_kev".into(),
            attack_type,
            severity: severity.into(),
            ioc_type: "cve".into(),
            ioc_value: cve.to_string(),
            description,
            threat_pattern,
        });
    }
    out
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────

/// Parse the AbuseIPDB blacklist JSON response.
/// Requires the response body already fetched with the API key header.
pub fn parse_abuseipdb(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let ips = match data["data"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let mut out = Vec::new();

    for entry in ips {
        let ip    = entry["ipAddress"].as_str().unwrap_or("");
        let score = entry["abuseConfidenceScore"].as_u64().unwrap_or(0);
        let country = entry["countryCode"].as_str().unwrap_or("??");
        let last_reported = entry["lastReportedAt"].as_str().unwrap_or("");
        if ip.is_empty() { continue; }

        let sev = if score > 95 { "HIGH" } else { "MEDIUM" };

        let categories = entry["abuseCategories"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|c| c.as_u64())
                .map(abuseipdb_category_name)
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_else(|| "malicious activity".to_string());

        let attack_type = categories_to_attack(&categories);
        let description = format!("Reported malicious IP from {} — confidence {}%", country, score);
        let threat_pattern = format!(
            "IP {} ({}): confidence {}%, reported for: {}. Last seen: {}. \
             Actively targeting internet-facing services.",
            ip, country, score, categories, last_reported
        );

        out.push(ThreatIntelEntry {
            source: "abuseipdb".into(),
            attack_type,
            severity: sev.into(),
            ioc_type: "ip".into(),
            ioc_value: ip.to_string(),
            description,
            threat_pattern,
        });
    }
    out
}

// ── AlienVault OTX ───────────────────────────────────────────────────────────

/// Parse OTX pulse subscriptions JSON response. Returns up to 20 IOCs per pulse.
pub fn parse_otx(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let pulses = match data["results"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let mut out = Vec::new();

    for pulse in pulses {
        let name    = pulse["name"].as_str().unwrap_or("");
        let desc    = pulse["description"].as_str().unwrap_or("");
        let author  = pulse["author_name"].as_str().unwrap_or("");
        let tags    = pulse["tags"].as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let tlp     = pulse["tlp"].as_str().unwrap_or("white");
        let attack_type = classify_attack(name, desc);

        let threat_pattern = format!(
            "Threat pulse '{}' by {}. Tags: {}. TLP: {}. {}",
            name, author, tags, tlp,
            if !desc.is_empty() { desc.chars().take(300).collect::<String>() }
            else { "No description.".into() }
        );
        let desc_short = format!("OTX pulse: {} [{}]", name, tags);

        if let Some(indicators) = pulse["indicators"].as_array() {
            for ioc in indicators.iter().take(20) {
                let ioc_type = ioc["type"].as_str().unwrap_or("");
                let ioc_val  = ioc["indicator"].as_str().unwrap_or("");
                if ioc_val.is_empty() { continue; }

                out.push(ThreatIntelEntry {
                    source: "otx".into(),
                    attack_type: attack_type.clone(),
                    severity: "MEDIUM".into(),
                    ioc_type: ioc_type.to_string(),
                    ioc_value: ioc_val.to_string(),
                    description: desc_short.clone(),
                    threat_pattern: threat_pattern.clone(),
                });
            }
        }
    }
    out
}

// ── Emerging Threats ─────────────────────────────────────────────────────────

/// Parse an Emerging Threats .rules file (plain text).
/// Groups by classtype and returns one entry per attack category.
pub fn parse_emerging_threats(text: &str) -> Vec<ThreatIntelEntry> {
    let mut categories: std::collections::HashMap<String, (u32, Vec<String>)> = Default::default();

    for line in text.lines().take(500) {
        if line.starts_with('#') { continue; }
        let classtype = line.split("classtype:").nth(1)
            .and_then(|s| s.split(';').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let msg = line.split("msg:\"").nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
            .unwrap_or_default();
        if classtype.is_empty() { continue; }
        let entry = categories.entry(classtype_to_attack(&classtype)).or_insert((0, vec![]));
        entry.0 += 1;
        if entry.1.len() < 3 && !msg.is_empty() {
            entry.1.push(msg);
        }
    }

    categories.into_iter().map(|(attack_type, (count, examples))| {
        ThreatIntelEntry {
            source:      "emerging_threats".into(),
            attack_type: attack_type.clone(),
            severity:    "MEDIUM".into(),
            ioc_type:    String::new(),
            ioc_value:   String::new(),
            description: format!("{} active rules in current events", count),
            threat_pattern: format!(
                "Emerging Threats: {} active rules for {} attack type. Examples: {}.",
                count, attack_type, examples.join(" | ")
            ),
        }
    }).collect()
}

// ── Feodo Tracker (abuse.ch) ─────────────────────────────────────────────────

/// Parse the Feodo Tracker recommended IP blocklist JSON.
/// Returns one entry per confirmed botnet C2 IP.
/// Feed: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
pub fn parse_feodo(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let entries = match data.as_array() {
        Some(v) => v,
        None    => return vec![],
    };
    let mut out = Vec::new();

    for entry in entries {
        let ip      = entry["ip_address"].as_str().unwrap_or("");
        let port    = entry["dst_port"].as_u64().unwrap_or(0);
        let malware = entry["malware"].as_str().unwrap_or("botnet");
        let status  = entry["status"].as_str().unwrap_or("");
        let country = entry["country"].as_str().unwrap_or("??");
        let last_seen = entry["last_online"].as_str().unwrap_or("");

        if ip.is_empty() { continue; }
        // Only include confirmed active C2 servers
        if status == "offline" { continue; }

        let ioc_value = if port > 0 {
            format!("{}:{}", ip, port)
        } else {
            ip.to_string()
        };

        let description = format!(
            "{} C2 server in {} — confirmed botnet infrastructure",
            malware, country
        );
        let threat_pattern = format!(
            "Feodo Tracker: confirmed {} C2 at {} ({}). Port: {}. Last active: {}. \
             This IP is part of active botnet infrastructure. Block immediately.",
            malware, ip, country, port, last_seen
        );

        out.push(ThreatIntelEntry {
            source:      "feodo".into(),
            attack_type: "c2_communication".into(),
            severity:    "HIGH".into(),
            ioc_type:    "ip".into(),
            ioc_value,
            description,
            threat_pattern,
        });
    }
    out
}

// ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────

/// Parse the URLhaus recent URLs JSON response.
/// Returns IOC entries for active malware distribution URLs and their domains.
/// Feed: https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/
pub fn parse_urlhaus(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let urls = match data["urls"].as_array() {
        Some(v) => v,
        None    => return vec![],
    };
    let mut out = Vec::new();
    let mut seen_hosts: std::collections::HashSet<String> = Default::default();

    for entry in urls {
        let url_status = entry["url_status"].as_str().unwrap_or("");
        // Skip URLs already taken down — focus on active threats
        if url_status == "offline" { continue; }

        let url      = entry["url"].as_str().unwrap_or("");
        let host     = entry["host"].as_str().unwrap_or("");
        let tags     = entry["tags"].as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let threat   = entry["threat"].as_str().unwrap_or("malware");
        let date_added = entry["date_added"].as_str().unwrap_or("");

        if url.is_empty() { continue; }

        let malware_names: Vec<String> = entry["payloads"].as_array()
            .map(|p| p.iter()
                .filter_map(|pl| pl["signature"].as_str())
                .take(3)
                .map(|s| s.to_string())
                .collect())
            .unwrap_or_default();
        let malware_str = if malware_names.is_empty() { threat.to_string() }
                          else { malware_names.join(", ") };

        let attack_type = if tags.contains("Emotet") || tags.contains("TrickBot")
                          || malware_str.to_lowercase().contains("rat") {
            "c2_communication"
        } else {
            "data_exfiltration"
        }.to_string();

        // Always add the URL itself
        out.push(ThreatIntelEntry {
            source:      "urlhaus".into(),
            attack_type: attack_type.clone(),
            severity:    "HIGH".into(),
            ioc_type:    "url".into(),
            ioc_value:   url.to_string(),
            description: format!("Active malware distribution URL — {}", malware_str),
            threat_pattern: format!(
                "URLhaus: active malware URL hosting {} (status: {}). \
                 Host: {}. Tags: {}. Added: {}. \
                 Downloading from this URL delivers malicious payloads.",
                malware_str, url_status, host, tags, date_added
            ),
        });

        // Also add the host as a domain IOC — deduplicated across URLs from same host
        if !host.is_empty() && seen_hosts.insert(host.to_string()) {
            let ioc_type = if host.parse::<std::net::IpAddr>().is_ok() { "ip" } else { "domain" };
            out.push(ThreatIntelEntry {
                source:      "urlhaus".into(),
                attack_type: attack_type.clone(),
                severity:    "HIGH".into(),
                ioc_type:    ioc_type.to_string(),
                ioc_value:   host.to_string(),
                description: format!("Host serving malware — {}", malware_str),
                threat_pattern: format!(
                    "URLhaus: host {} is actively distributing malware ({}). \
                     Block all traffic to this host.",
                    host, malware_str
                ),
            });
        }
    }
    out
}

// ── ThreatFox (abuse.ch) ──────────────────────────────────────────────────────

/// Parse the ThreatFox IOC response (POST query for recent IOCs).
/// Handles IPs, domains, URLs, and file hashes for known malware families.
pub fn parse_threatfox(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let iocs = match data["data"].as_array() {
        Some(v) => v,
        None    => return vec![],
    };
    let mut out = Vec::new();

    for ioc in iocs {
        let ioc_value  = ioc["ioc"].as_str().unwrap_or("");
        let ioc_type   = ioc["ioc_type"].as_str().unwrap_or("");
        let malware    = ioc["malware"].as_str().unwrap_or("unknown");
        let confidence = ioc["confidence_level"].as_u64().unwrap_or(0);
        let threat_type= ioc["threat_type"].as_str().unwrap_or("malware");
        let first_seen = ioc["first_seen"].as_str().unwrap_or("");
        let last_seen  = ioc["last_seen"].as_str().unwrap_or("");
        let reporter   = ioc["reporter"].as_str().unwrap_or("community");
        let tags       = ioc["tags"].as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();

        if ioc_value.is_empty() || confidence < 50 { continue; }

        let normalized_type = match ioc_type {
            "ip:port"  => "ip",
            "domain"   => "domain",
            "url"      => "url",
            "md5_hash" | "sha1_hash" | "sha256_hash" => "hash",
            other      => other,
        };

        // ip:port format — strip port for the IOC value so it matches network flow lookups
        let ioc_val_clean = if ioc_type == "ip:port" {
            ioc_value.split(':').next().unwrap_or(ioc_value).to_string()
        } else {
            ioc_value.to_string()
        };

        let severity = if confidence >= 90 { "HIGH" } else { "MEDIUM" };
        let attack_type = classify_attack(malware, threat_type);

        let description = format!(
            "{} IOC for {} — confidence {}%",
            threat_type, malware, confidence
        );
        let threat_pattern = format!(
            "ThreatFox: {} IOC ({}) associated with {}. Threat type: {}. \
             Confidence: {}%. Reporter: {}. Tags: {}. First seen: {}. Last seen: {}.",
            normalized_type, ioc_value, malware, threat_type,
            confidence, reporter, tags, first_seen, last_seen
        );

        out.push(ThreatIntelEntry {
            source:      "threatfox".into(),
            attack_type,
            severity:    severity.into(),
            ioc_type:    normalized_type.to_string(),
            ioc_value:   ioc_val_clean,
            description,
            threat_pattern,
        });
    }
    out
}

// ── Spamhaus DROP / EDROP ────────────────────────────────────────────────────

/// Parse a Spamhaus DROP or EDROP plain-text file.
/// Lines starting with ';' are comments. Each data line is:
///   `1.10.16.0/20 ; SBL123456`
/// Returns one entry per CIDR with ioc_type = "cidr".
/// Both DROP and EDROP use the same format — call this for each.
pub fn parse_spamhaus_drop(text: &str, label: &str) -> Vec<ThreatIntelEntry> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') { continue; }

        // Format: CIDR ; SBL_reference
        let mut parts = line.splitn(2, ';');
        let cidr = parts.next().unwrap_or("").trim();
        let sbl  = parts.next().unwrap_or("").trim();

        // Basic validation — must look like a CIDR
        if !cidr.contains('/') { continue; }
        let (ip_part, prefix_part) = match cidr.split_once('/') {
            Some(p) => p,
            None    => continue,
        };
        // IP must be valid, prefix must be numeric
        if ip_part.parse::<std::net::Ipv4Addr>().is_err() { continue; }
        if prefix_part.parse::<u8>().is_err()              { continue; }

        let description = format!(
            "Spamhaus {}: hijacked/criminal-controlled network block {}",
            label, cidr
        );
        let threat_pattern = format!(
            "Spamhaus {}: CIDR {} is controlled by organized crime or cybercriminal groups ({}). \
             Any traffic to/from this range should be treated as high-risk. \
             These blocks are not legitimately routed and are used exclusively for malicious activity.",
            label, cidr, sbl
        );

        out.push(ThreatIntelEntry {
            source:      "spamhaus_drop".into(),
            attack_type: "general_threat".into(),
            severity:    "HIGH".into(),
            ioc_type:    "cidr".into(),
            ioc_value:   cidr.to_string(),
            description,
            threat_pattern,
        });
    }
    out
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Classify an attack type from free-text (rule title, description, CVE id).
pub fn classify_attack(a: &str, b: &str) -> String {
    let t = format!("{} {}", a, b).to_lowercase();
    if t.contains("ransom")                                                   { return "ransomware".into(); }
    if t.contains("credential") || t.contains("brute") || t.contains("phish") { return "credential_attack".into(); }
    if t.contains("exploit") || t.contains("rce")                             { return "exploitation".into(); }
    if t.contains("lateral") || t.contains("pivot") || t.contains("smb")     { return "lateral_movement".into(); }
    if t.contains("c2") || t.contains("beacon") || t.contains("rat ")        { return "c2_communication".into(); }
    if t.contains("exfil") || t.contains("stealer")                          { return "data_exfiltration".into(); }
    if t.contains("scan") || t.contains("recon")                             { return "recon".into(); }
    if t.contains("supply chain") || t.contains("package")                   { return "supply_chain".into(); }
    "general_threat".into()
}

pub fn classtype_to_attack(ct: &str) -> String {
    match ct {
        "trojan-activity"  => "c2_communication",
        "attempted-user"   => "exploitation",
        "attempted-admin"  => "exploitation",
        "network-scan"     => "recon",
        "attempted-recon"  => "recon",
        "credential-theft" => "credential_attack",
        _                  => "general_threat",
    }.into()
}

pub fn abuseipdb_category_name(code: u64) -> &'static str {
    match code {
        3  => "fraud orders",    4  => "DDoS attack",
        5  => "FTP brute force", 6  => "ping of death",
        7  => "phishing",        8  => "fraud VoIP",
        9  => "open proxy",      10 => "web spam",
        11 => "email spam",      12 => "blog spam",
        13 => "VPN IP",          14 => "port scan",
        15 => "hacking",         16 => "SQL injection",
        17 => "spoofing",        18 => "brute force",
        19 => "bad web bot",     20 => "exploited host",
        21 => "web app attack",  22 => "SSH brute force",
        23 => "IoT targeted",    _  => "malicious activity",
    }
}

pub fn categories_to_attack(cats: &str) -> String {
    let c = cats.to_lowercase();
    if c.contains("brute") || c.contains("ssh") { return "credential_attack".into(); }
    if c.contains("scan")                        { return "recon".into(); }
    if c.contains("phish")                       { return "credential_attack".into(); }
    if c.contains("exploit") || c.contains("sql"){ return "exploitation".into(); }
    if c.contains("ddos")                        { return "denial_of_service".into(); }
    "general_threat".into()
}
