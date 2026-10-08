use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// In-memory set of trusted cloud infrastructure ranges.
/// Populated at startup and refreshed every 24h from official provider IP lists.
/// Shared via Arc<RwLock<>> — reads are cheap (no clone of the large set).
#[derive(Default)]
pub struct TrustedRanges {
    /// Pre-parsed IPv4 CIDR networks from AWS / Google / Cloudflare / Fastly official lists
    ipv4_nets: Vec<(u32, u32)>, // (start, end) inclusive — O(N) scan but N~5000, sub-microsecond
    /// SNI hostname suffixes that are always trusted (e.g. ".amazonaws.com")
    domain_suffixes: HashSet<String>,
    /// ASN org-name keywords (uppercase) for ASN-DB fallback (e.g. "AMAZON", "GOOGLE")
    asn_keywords: HashSet<String>,
}

impl TrustedRanges {
    /// True if the IPv4 address falls inside any known cloud provider CIDR.
    /// ipv4_nets is kept sorted by start address so we can binary-search to
    /// O(log N) instead of O(N) — called on every Sigma hit.
    pub fn is_trusted_ip(&self, ip: &str) -> bool {
        let n = match parse_ipv4_u32(ip) { Some(n) => n, None => return false };
        // partition_point returns the first index where start > n.
        // Candidates are the entries just before that point; we check a small
        // window to handle nested CIDRs (e.g. a /8 containing a /24).
        let idx = self.ipv4_nets.partition_point(|(s, _)| *s <= n);
        let low = idx.saturating_sub(8);
        self.ipv4_nets[low..idx].iter().any(|(s, e)| n >= *s && n <= *e)
    }

    /// True if the SNI hostname ends with a trusted cloud domain suffix.
    pub fn is_trusted_domain(&self, domain: &str) -> bool {
        if domain.is_empty() { return false; }
        let d = domain.to_lowercase();
        self.domain_suffixes.iter().any(|suf| d.ends_with(suf.as_str()))
    }

    /// True if the ASN org string contains a trusted cloud provider keyword.
    pub fn is_trusted_asn(&self, org: &str) -> bool {
        if org.is_empty() { return false; }
        let o = org.to_uppercase();
        self.asn_keywords.iter().any(|kw| o.contains(kw.as_str()))
    }

    /// Hot-add a single ASN keyword without waiting for the next 23h refresh cycle.
    pub fn add_asn_keyword(&mut self, keyword: &str) {
        self.asn_keywords.insert(keyword.to_uppercase());
    }

    /// Combined check: trusted if IP matches CIDR OR domain matches suffix OR ASN matches keyword.
    /// Optionally falls back to ASN database lookup if CIDR miss (handles gaps between refreshes).
    pub fn is_trusted(
        &self,
        dst_ip: &str,
        sni: &str,
        asn_db: &Option<crate::enrichment::AsnLookup>,
    ) -> bool {
        if self.is_trusted_ip(dst_ip) { return true; }
        if self.is_trusted_domain(sni) { return true; }
        // ASN fallback — catches new IP ranges not yet in the downloaded list
        if let Some(db) = asn_db {
            if let Some(info) = db.lookup(dst_ip) {
                if self.is_trusted_asn(&info.org) { return true; }
            }
        }
        false
    }


}

// ── CIDR helpers ─────────────────────────────────────────────────────────────

fn parse_ipv4_u32(ip: &str) -> Option<u32> {
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    Some(u32::from(addr))
}

fn cidr_to_range(cidr: &str) -> Option<(u32, u32)> {
    let (base_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    let base   = parse_ipv4_u32(base_str)?;
    let mask   = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let start  = base & mask;
    let end    = start | !mask;
    Some((start, end))
}

// ── Background updater ────────────────────────────────────────────────────────

/// Spawn a background task that keeps `trusted` up to date on THIS instance.
/// Downloads official cloud IP range JSON files at startup then every 24h.
///
/// Deliberately NOT leader-gated, unlike the other 11 threat background
/// tasks: `trusted` backs the synchronous per-event trusted-cloud check on
/// the live Kafka ingestion path (api/mod.rs), which every instance runs
/// regardless of leadership. This task only reads public data (AWS/Google/
/// Cloudflare/Fastly IP-range JSON, a domain-suffix setting) into a purely
/// local cache - there's no shared-write duplication to avoid by gating it,
/// unlike entity_scorer's ClickHouse upsert. The old doc comment claimed
/// gating was safe "because this task is already leader-only" - circular
/// reasoning, not an actual reason; it left every non-leader instance's
/// `trusted` cache permanently empty (TrustedRanges::default()) for its
/// entire lifetime, silently disabling trusted-cloud suppression for
/// whatever share of live traffic that instance's own Kafka partitions
/// happened to be processing.
pub fn spawn_trust_updater(
    trusted: Arc<RwLock<TrustedRanges>>,
    redis:   Arc<redis::Client>,
    asn:     Arc<Option<crate::enrichment::AsnLookup>>,
    ch:      Arc<crate::storage::ClickhouseStorage>,
) {
    tokio::spawn(async move {
        loop {
            refresh(&trusted, &redis, &asn, &ch).await;
            // 23h sleep so refresh always completes well before the 24h cache window
            tokio::time::sleep(std::time::Duration::from_secs(23 * 3600)).await;
        }
    });
}

async fn refresh(
    trusted: &Arc<RwLock<TrustedRanges>>,
    redis:   &Arc<redis::Client>,
    _asn:    &Arc<Option<crate::enrichment::AsnLookup>>,
    ch:      &Arc<crate::storage::ClickhouseStorage>,
) {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("NDR-Engine/1.0")
        .build()
        .unwrap_or_default();

    let mut nets: Vec<(u32, u32)> = Vec::with_capacity(8192);

    // ── Official cloud provider IP range sources ──────────────────────────
    let sources: &[(&str, &str)] = &[
        ("AWS",        "https://ip-ranges.amazonaws.com/ip-ranges.json"),
        ("Google",     "https://www.gstatic.com/ipranges/goog.json"),
        ("Cloudflare", "https://www.cloudflare.com/ips-v4"),
        ("Fastly",     "https://api.fastly.com/public-ip-list"),
    ];

    for (name, url) in sources {
        let count_before = nets.len();
        match http.get(*url).send().await {
            Ok(resp) => {
                match name {
                    &"AWS" => {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            for p in data["prefixes"].as_array().cloned().unwrap_or_default() {
                                if let Some(c) = p["ip_prefix"].as_str() {
                                    if let Some(r) = cidr_to_range(c) { nets.push(r); }
                                }
                            }
                        }
                    }
                    &"Google" => {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            for p in data["prefixes"].as_array().cloned().unwrap_or_default() {
                                if let Some(c) = p.get("ipv4Prefix").and_then(|v| v.as_str()) {
                                    if let Some(r) = cidr_to_range(c) { nets.push(r); }
                                }
                            }
                        }
                    }
                    _ => {
                        // Cloudflare + Fastly return plain-text CIDR lists (one per line)
                        let text = if *name == "Fastly" {
                            resp.json::<serde_json::Value>().await.ok()
                                .and_then(|d| {
                                    d["addresses"].as_array()
                                        .map(|arr| arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                            .join("\n"))
                                })
                                .unwrap_or_default()
                        } else {
                            resp.text().await.unwrap_or_default()
                        };
                        for line in text.lines() {
                            let c = line.trim();
                            if !c.is_empty() {
                                if let Some(r) = cidr_to_range(c) { nets.push(r); }
                            }
                        }
                    }
                }
                info!("cloud_trust: {} → {} ranges added", name, nets.len() - count_before);
            }
            Err(e) => warn!("cloud_trust: {} fetch failed — {}", name, e),
        }
    }

    // ── Domain suffixes — read from ndr.settings, fall back to defaults ──
    const DEFAULT_DOMAINS: &str = concat!(
        ".amazonaws.com,.cloudfront.net,.compute.amazonaws.com,.aws.amazon.com,.awsstatic.com,",
        ".google.com,.googleapis.com,.gstatic.com,.googleusercontent.com,.googlevideo.com,",
        ".microsoft.com,.azure.com,.windows.net,.microsoftonline.com,.azure-dns.com,",
        ".trafficmanager.net,.sharepoint.com,.office.com,.office365.com,",
        ".cloudflare.com,.cloudflare.net,.cloudflare-dns.com,",
        ".akamai.net,.akamaiedge.net,.akamaitechnologies.com,",
        ".fastly.net,.fastlylb.net,.cdn77.com,.stackpath.com,.edgecastcdn.net,",
        ".apple.com,.icloud.com,.mzstatic.com,",
        ".whatsapp.net,.whatsapp.com,.fbcdn.net,.facebook.com,.meta.com,",
        ".okta.com,.salesforce.com,.twilio.com,.stripe.com"
    );
    let dom_str = ch.get_global_setting("trusted_cloud_domains").await
        .unwrap_or_else(|| DEFAULT_DOMAINS.to_string());
    let domain_suffixes: HashSet<String> = dom_str.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // ── ASN org keywords — read from ndr.settings, fall back to defaults ──
    const DEFAULT_ASN_KEYWORDS: &str =
        "AMAZON,GOOGLE,MICROSOFT,CLOUDFLARE,AKAMAI,FASTLY,APPLE,ALIBABA,META,FACEBOOK,EDGECAST,STACKPATH,CDN77";
    let kw_str = ch.get_global_setting("trusted_cloud_asn_keywords").await
        .unwrap_or_else(|| DEFAULT_ASN_KEYWORDS.to_string());
    let asn_keywords: HashSet<String> = kw_str.split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    // ── Admin-defined CIDRs from ndr.settings (trusted_cloud_cidrs) ──────
    // Any CIDR added here is treated as trusted cloud — no sensitive-country
    // scoring, no cloud-traffic suppression bypass. Admins can add Azure,
    // private clouds, on-prem CDN ranges etc. without touching code.
    let custom_cidr_str = ch.get_global_setting("trusted_cloud_cidrs").await
        .unwrap_or_default();
    let mut custom_count = 0usize;
    for cidr in custom_cidr_str.split(',') {
        let c = cidr.trim();
        if c.is_empty() { continue; }
        if let Some(r) = cidr_to_range(c) {
            nets.push(r);
            custom_count += 1;
        } else {
            warn!("cloud_trust: invalid CIDR in trusted_cloud_cidrs: '{}'", c);
        }
    }

    // Sort by start address so is_trusted_ip can binary-search in O(log N)
    nets.sort_unstable_by_key(|r| r.0);

    let total     = nets.len();
    let dom_count = domain_suffixes.len();
    let kw_count  = asn_keywords.len();

    // Atomic swap — readers see either old or new, never partial
    {
        let mut guard = trusted.write().await;
        guard.ipv4_nets       = nets;
        guard.domain_suffixes = domain_suffixes;
        guard.asn_keywords    = asn_keywords;
    }

    info!("cloud_trust: updated — {} IPv4 ranges ({} custom), {} domain suffixes, {} ASN keywords",
          total, custom_count, dom_count, kw_count);

    // Heartbeat in Redis — visible to ops tooling, no functional role
    if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
        let _: Result<(), _> = redis::cmd("SETEX")
            .arg("ndr:cloud_trust_refreshed_at")
            .arg(90_000u64) // 25h TTL — always alive between 23h refreshes
            .arg(chrono::Utc::now().timestamp().to_string())
            .query_async(&mut conn).await;
    }
}
