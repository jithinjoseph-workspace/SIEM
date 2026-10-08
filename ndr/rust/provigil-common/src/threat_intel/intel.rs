use dashmap::DashSet;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

// Legitimate shared-hosting platforms that attackers abuse to stage payloads.
// Extracting the bare hostname from a URLhaus URL like
//   https://raw.githubusercontent.com/evil/repo/malware.exe
// would mark the entire platform as malicious — skip these.
const SHARED_HOSTING: &[&str] = &[
    "raw.githubusercontent.com", "githubusercontent.com",
    "github.com", "github.io",
    "gitlab.com", "bitbucket.org",
    "drive.google.com", "docs.google.com",
    "storage.googleapis.com", "googleapis.com",
    "blob.core.windows.net", "onedrive.live.com", "sharepoint.com",
    "pastebin.com", "paste.ee", "hastebin.com",
    "dropbox.com", "dl.dropboxusercontent.com",
    "amazonaws.com", "s3.amazonaws.com",
    "cloudflare.com",
    "discord.com", "discordapp.com", "cdn.discordapp.com",
    "t.me", "telegram.org",
    "mediafire.com", "sendspace.com", "transfer.sh",
];

fn is_shared_hosting(host: &str) -> bool {
    let h = host.to_lowercase();
    SHARED_HOSTING.iter().any(|&s| h == s || h.ends_with(&format!(".{}", s)))
}

/// In-memory IOC cache shared across all engines (ndr-engine, siem-engine, etc.).
/// Populated by calling `refresh()` or `refresh_with_settings()` on startup and
/// periodically thereafter. All lookups are synchronous and lock-free (DashSet).
#[derive(Debug, Clone, Default)]
pub struct ThreatIntelSnapshot {
    pub malicious_ips:     Vec<IpAddr>,
    pub malicious_hashes:  Vec<String>,
    pub malicious_domains: Vec<String>,
    pub malicious_urls:    Vec<String>,
    pub malicious_ja3:     Vec<String>,
    pub malicious_cidrs:   Vec<IpNetwork>,
}

#[derive(Clone)]
pub struct ThreatIntel {
    pub malicious_ips:     Arc<DashSet<IpAddr>>,
    pub malicious_hashes:  Arc<DashSet<String>>,
    pub malicious_domains: Arc<DashSet<String>>,
    pub malicious_urls:    Arc<DashSet<String>>,
    pub malicious_ja3:     Arc<DashSet<String>>,
    /// Spamhaus DROP/EDROP — criminal-controlled CIDR blocks.
    /// Uses std::sync::RwLock (not tokio) so is_malicious_ip() stays synchronous.
    pub malicious_cidrs:   Arc<RwLock<Vec<IpNetwork>>>,
    pub last_refreshed_at: Arc<AtomicU64>,
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            malicious_ips:     Arc::new(DashSet::new()),
            malicious_hashes:  Arc::new(DashSet::new()),
            malicious_domains: Arc::new(DashSet::new()),
            malicious_urls:    Arc::new(DashSet::new()),
            malicious_ja3:     Arc::new(DashSet::new()),
            malicious_cidrs:   Arc::new(RwLock::new(Vec::new())),
            last_refreshed_at: Arc::new(AtomicU64::new(0)),
        }
    }

    // ── Snapshot / atomic swap ───────────────────────────────────────────────

    pub fn snapshot(&self) -> ThreatIntelSnapshot {
        ThreatIntelSnapshot {
            malicious_ips:     self.malicious_ips.iter().map(|ip| (*ip).clone()).collect(),
            malicious_hashes:  self.malicious_hashes.iter().map(|v| (*v).clone()).collect(),
            malicious_domains: self.malicious_domains.iter().map(|v| (*v).clone()).collect(),
            malicious_urls:    self.malicious_urls.iter().map(|v| (*v).clone()).collect(),
            malicious_ja3:     self.malicious_ja3.iter().map(|v| (*v).clone()).collect(),
            malicious_cidrs:   self.malicious_cidrs.read().map(|v| v.clone()).unwrap_or_default(),
        }
    }

    pub fn snapshot_entries(&self, source: &str) -> Vec<crate::threat_intel::ThreatIntelEntry> {
        let snap = self.snapshot();
        let mut entries = Vec::new();

        for ip in snap.malicious_ips {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "general_threat".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "ip".to_string(),
                ioc_value: ip.to_string(),
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        for hash in snap.malicious_hashes {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "file_hash".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "hash".to_string(),
                ioc_value: hash,
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        for domain in snap.malicious_domains {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "c2".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "domain".to_string(),
                ioc_value: domain,
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        for url in snap.malicious_urls {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "malware_distribution".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "url".to_string(),
                ioc_value: url,
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        for ja3 in snap.malicious_ja3 {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "ja3".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "ja3".to_string(),
                ioc_value: ja3,
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        for cidr in snap.malicious_cidrs {
            entries.push(crate::threat_intel::ThreatIntelEntry {
                source: source.to_string(),
                attack_type: "botnet_c2".to_string(),
                severity: "HIGH".to_string(),
                ioc_type: "cidr".to_string(),
                ioc_value: cidr.to_string(),
                description: "Runtime threat intel snapshot".to_string(),
                threat_pattern: "runtime_snapshot".to_string(),
            });
        }

        entries
    }

    pub fn replace_snapshot(&self, snapshot: ThreatIntelSnapshot) {
        self.malicious_ips.clear();
        for ip in snapshot.malicious_ips { self.malicious_ips.insert(ip); }

        self.malicious_hashes.clear();
        for hash in snapshot.malicious_hashes { self.malicious_hashes.insert(hash); }

        self.malicious_domains.clear();
        for domain in snapshot.malicious_domains { self.malicious_domains.insert(domain); }

        self.malicious_urls.clear();
        for url in snapshot.malicious_urls { self.malicious_urls.insert(url); }

        self.malicious_ja3.clear();
        for ja3 in snapshot.malicious_ja3 { self.malicious_ja3.insert(ja3); }

        if let Ok(mut guard) = self.malicious_cidrs.write() {
            *guard = snapshot.malicious_cidrs;
        }
    }

    // ── Counts ────────────────────────────────────────────────────────────────

    pub fn ip_count(&self)     -> usize { self.malicious_ips.len() }
    pub fn hash_count(&self)   -> usize { self.malicious_hashes.len() }
    pub fn domain_count(&self) -> usize { self.malicious_domains.len() }
    pub fn ja3_count(&self)    -> usize { self.malicious_ja3.len() }
    pub fn cidr_count(&self)   -> usize {
        self.malicious_cidrs.read().map(|v| v.len()).unwrap_or(0)
    }

    pub fn last_refresh_iso(&self) -> String {
        let ts = self.last_refreshed_at.load(Ordering::Relaxed);
        if ts == 0 { return "never".to_string(); }
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        let Ok(addr) = IpAddr::from_str(ip) else { return false };
        if self.malicious_ips.contains(&addr) { return true; }
        if let Ok(cidrs) = self.malicious_cidrs.read() {
            if cidrs.iter().any(|net| net.contains(addr)) { return true; }
        }
        false
    }

    pub fn is_malicious_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.contains(&hash.to_lowercase())
    }

    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        if self.malicious_domains.contains(&d) { return true; }
        // Also check parent domains — subdomain of a malicious domain is malicious
        let parts: Vec<&str> = d.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.malicious_domains.contains(&parent) { return true; }
        }
        false
    }

    pub fn is_malicious_ja3(&self, hash: &str) -> bool {
        self.malicious_ja3.contains(&hash.to_lowercase())
    }

    // ── Manual IOC insertion (analyst watchlist / API push) ───────────────────

    pub fn add_ioc(&self, ioc_type: &str, value: &str) {
        match ioc_type {
            "ip" => {
                if let Ok(ip) = IpAddr::from_str(value) {
                    self.malicious_ips.insert(ip);
                }
            }
            "hash" | "md5" | "sha256" | "sha1" => {
                self.malicious_hashes.insert(value.to_lowercase());
            }
            "domain" | "hostname" => {
                self.malicious_domains.insert(value.to_lowercase());
            }
            "url" => {
                self.malicious_urls.insert(value.to_lowercase());
                if let Some(host) = extract_host(value) {
                    if let Ok(ip) = IpAddr::from_str(&host) {
                        self.malicious_ips.insert(ip);
                    } else if !is_shared_hosting(&host) {
                        self.malicious_domains.insert(host);
                    }
                }
            }
            _ => {}
        }
    }

    // ── Refresh — all feeds ───────────────────────────────────────────────────

    pub async fn refresh(&self) {
        tokio::join!(
            self.refresh_feodo(),
            self.refresh_urlhaus(),
            self.refresh_malware_bazaar(),
            self.refresh_ja3_blocklist(),
            self.refresh_spamhaus(),
        );
        self.stamp_refreshed();
        info!(
            "Threat intel refresh complete — {} IPs, {} hashes, {} domains, {} JA3, {} CIDRs",
            self.ip_count(), self.hash_count(), self.domain_count(),
            self.ja3_count(), self.cidr_count()
        );
    }

    /// Refresh with per-feed toggles (from tenant settings UI).
    pub async fn refresh_with_settings(
        &self,
        feodo_enabled:        bool,
        malwarebazaar_enabled: bool,
        urlhaus_enabled:      bool,
        custom_feed_url:      &str,
    ) {
        if feodo_enabled        { self.refresh_feodo().await;          } else { info!("Feodo disabled — skipping");        }
        if urlhaus_enabled      { self.refresh_urlhaus().await;        } else { info!("URLhaus disabled — skipping");      }
        if malwarebazaar_enabled{ self.refresh_malware_bazaar().await; } else { info!("MalwareBazaar disabled — skipping");}
        if !custom_feed_url.is_empty() { self.refresh_custom_feed(custom_feed_url).await; }
        // JA3 and Spamhaus always run — no toggle, always desirable
        self.refresh_ja3_blocklist().await;
        self.refresh_spamhaus().await;
        self.stamp_refreshed();
    }

    fn stamp_refreshed(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_refreshed_at.store(now, Ordering::Relaxed);
    }

    // ── Individual feed refreshers ────────────────────────────────────────────

    async fn refresh_feodo(&self) {
        let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv";
        let Ok(resp) = reqwest::get(url).await else { warn!("Feodo fetch error"); return; };
        let Ok(text) = resp.text().await         else { warn!("Feodo body error");  return; };

        let mut new_ips: Vec<IpAddr> = Vec::new();
        let mut loaded = 0usize;
        let mut header_parsed = false;
        let mut ip_col = 0usize;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if !header_parsed {
                let cols: Vec<&str> = line.split(',').collect();
                for (i, col) in cols.iter().enumerate() {
                    let c = col.trim_matches('"').to_lowercase();
                    if c == "dst_ip" || c == "ip_address" { ip_col = i; break; }
                }
                header_parsed = true;
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            if let Some(ip_str) = cols.get(ip_col) {
                let ip = ip_str.trim_matches('"').trim();
                if let Ok(addr) = IpAddr::from_str(ip) { new_ips.push(addr); loaded += 1; }
            }
        }

        let mut snap = self.snapshot();
        snap.malicious_ips = new_ips;
        self.replace_snapshot(snap);
        info!("Feodo: {} malicious IPs loaded", loaded);
    }

    async fn refresh_malware_bazaar(&self) {
        let url = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
        let Ok(resp) = reqwest::get(url).await else { warn!("MalwareBazaar fetch error"); return; };
        let Ok(text) = resp.text().await         else { warn!("MalwareBazaar body error");  return; };

        let mut new_hashes: Vec<String> = Vec::new();
        let mut loaded = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                new_hashes.push(line.to_lowercase());
                loaded += 1;
            }
        }

        let mut snap = self.snapshot();
        snap.malicious_hashes = new_hashes;
        self.replace_snapshot(snap);
        info!("MalwareBazaar: {} malicious hashes loaded", loaded);
    }

    async fn refresh_ja3_blocklist(&self) {
        let url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";
        let Ok(resp) = reqwest::get(url).await else { warn!("JA3 blocklist fetch error"); return; };
        let Ok(text) = resp.text().await         else { warn!("JA3 blocklist body error");  return; };

        let mut new_ja3: Vec<String> = Vec::new();
        let mut loaded = 0usize;
        let mut header_skipped = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if !header_skipped { header_skipped = true; continue; }
            if let Some(hash) = line.split(',').next() {
                let h = hash.trim_matches('"').trim();
                if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                    new_ja3.push(h.to_lowercase());
                    loaded += 1;
                }
            }
        }

        let mut snap = self.snapshot();
        snap.malicious_ja3 = new_ja3;
        self.replace_snapshot(snap);
        info!("JA3 blocklist: {} malicious fingerprints loaded", loaded);
    }

    async fn refresh_spamhaus(&self) {
        let (drop_res, edrop_res) = tokio::join!(
            reqwest::get("https://www.spamhaus.org/drop/drop.txt"),
            reqwest::get("https://www.spamhaus.org/drop/edrop.txt"),
        );
        let mut cidrs: Vec<IpNetwork> = Vec::new();
        for result in [drop_res, edrop_res] {
            let Ok(resp) = result                  else { warn!("Spamhaus fetch error"); continue; };
            let Ok(text) = resp.text().await       else { warn!("Spamhaus body error");  continue; };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(';') { continue; }
                let cidr = line.splitn(2, ';').next().unwrap_or("").trim();
                if let Ok(net) = cidr.parse::<IpNetwork>() { cidrs.push(net); }
            }
        }

        let count = cidrs.len();
        let mut snap = self.snapshot();
        snap.malicious_cidrs = cidrs;
        self.replace_snapshot(snap);
        info!("Spamhaus DROP+EDROP: {} criminal CIDR blocks loaded", count);
    }

    async fn refresh_urlhaus(&self) {
        let url = "https://urlhaus.abuse.ch/downloads/text_online/";
        let Ok(resp) = reqwest::get(url).await else { warn!("URLhaus fetch error"); return; };
        let Ok(text) = resp.text().await         else { warn!("URLhaus body error");  return; };

        let mut new_domains: Vec<String> = Vec::new();
        let mut new_urls: Vec<String> = Vec::new();
        let mut new_ips: Vec<IpAddr> = Vec::new();
        let mut loaded_domains = 0usize;
        let mut loaded_ips = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            new_urls.push(line.to_lowercase());
            if let Some(host) = extract_host(line) {
                if let Ok(ip) = IpAddr::from_str(&host) {
                    new_ips.push(ip); loaded_ips += 1;
                } else if !is_shared_hosting(&host) {
                    new_domains.push(host); loaded_domains += 1;
                }
            }
        }

        let mut snap = self.snapshot();
        snap.malicious_domains = new_domains;
        snap.malicious_urls = new_urls;
        snap.malicious_ips.extend(new_ips);
        self.replace_snapshot(snap);
        info!("URLhaus: {} malicious domains + {} IPs loaded", loaded_domains, loaded_ips);
    }

    async fn refresh_custom_feed(&self, url: &str) {
        let Ok(resp) = reqwest::get(url).await else { warn!("Custom feed fetch error: {}", url); return; };
        let Ok(text) = resp.text().await         else { warn!("Custom feed body error: {}", url);  return; };

        let mut new_ips: Vec<IpAddr> = Vec::new();
        let mut new_hashes: Vec<String> = Vec::new();
        let mut new_domains: Vec<String> = Vec::new();
        let (mut ips, mut hashes, mut domains) = (0usize, 0usize, 0usize);
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Ok(addr) = std::net::IpAddr::from_str(line) {
                new_ips.push(addr); ips += 1;
            } else if (line.len() == 32 || line.len() == 40 || line.len() == 64)
                && line.chars().all(|c| c.is_ascii_hexdigit())
            {
                new_hashes.push(line.to_lowercase()); hashes += 1;
            } else if line.contains('.') && !line.contains('/') {
                new_domains.push(line.to_lowercase()); domains += 1;
            }
        }

        let mut snap = self.snapshot();
        snap.malicious_ips.extend(new_ips);
        snap.malicious_hashes.extend(new_hashes);
        snap.malicious_domains.extend(new_domains);
        self.replace_snapshot(snap);
        info!("Custom feed: {} IPs, {} hashes, {} domains loaded from {}", ips, hashes, domains, url);
    }
}

fn extract_host(url: &str) -> Option<String> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    let host = url.split('/').next()?.split(':').next()?.to_lowercase().trim().to_string();
    if !host.is_empty() { Some(host) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_snapshot_replacement_preserves_malicious_iocs() {
        let ti = ThreatIntel::new();
        ti.add_ioc("ip", "1.2.3.4");

        let snap = ti.snapshot();
        let mut data = snap.clone();
        data.malicious_ips.push(IpAddr::from_str("5.6.7.8").unwrap());

        ti.replace_snapshot(data);

        assert!(ti.is_malicious_ip("1.2.3.4"));
        assert!(ti.is_malicious_ip("5.6.7.8"));
    }
}
