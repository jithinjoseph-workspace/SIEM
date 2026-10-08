use dashmap::DashMap;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub struct AssetIdentifier {
    oui_map: DashMap<String, String>,
}

impl AssetIdentifier {
    pub fn new() -> Self {
        let oui_map = DashMap::new();
        let oui_path = std::env::var("OUI_JSON").unwrap_or_else(|_| "data/oui_vendors.json".to_string());
        if let Ok(content) = fs::read_to_string(&oui_path) {
            if let Ok(json) = serde_json::from_str::<HashMap<String, String>>(&content) {
                for (k, v) in json {
                    oui_map.insert(k.to_uppercase(), v);
                }
                info!("Loaded {} OUI prefixes from disk.", oui_map.len());
            } else {
                tracing::warn!("Failed to parse OUI JSON at {}", oui_path);
            }
        } else {
            tracing::warn!("OUI JSON not found at {} — vendor lookup empty until first update.", oui_path);
        }
        Self { oui_map }
    }

    pub fn lookup_vendor(&self, mac: &str) -> String {
        let clean_mac = mac.replace('-', ":").to_uppercase();
        if clean_mac.len() >= 8 {
            let oui = &clean_mac[0..8];
            if let Some(v) = self.oui_map.get(oui) {
                return v.value().clone();
            }
        }
        "Unknown".to_string()
    }

    pub fn guess_device_type(&self, hostname: &str, vendor: &str, is_gateway: bool) -> String {
        let h = hostname.to_lowercase();
        let v = vendor.to_lowercase();

        if is_gateway { return "router".to_string(); }
        if h.contains("iphone") || (v.contains("apple") && h.contains("phone")) { return "phone".to_string(); }
        if h.contains("android") || h.contains("galaxy") || v.contains("samsung") { return "phone".to_string(); }
        if h.contains("macbook") || h.contains("imac") || h.contains("mac-") { return "laptop".to_string(); }
        if h.contains("lap") || h.contains("thinkpad") || h.contains("latitude") || h.contains("notebook") { return "laptop".to_string(); }
        if h.contains("pc") || h.contains("desktop") || h.contains("workstation") { return "desktop".to_string(); }
        if h.contains("print") || v.contains("hp") || v.contains("epson") || v.contains("brother") { return "printer".to_string(); }
        if h.contains("tv") || h.contains("cast") || h.contains("roku") || v.contains("roku") { return "tv".to_string(); }
        if h.contains("cam") || v.contains("ubiquiti") || v.contains("raspberry") || v.contains("espressif") || v.contains("sonoff") { return "iot".to_string(); }
        if h.contains("srv") || h.contains("server") { return "server".to_string(); }
        if h.contains("router") || h.contains("gateway") || h.contains("switch") || v.contains("cisco") || v.contains("tp-link") || v.contains("netgear") || v.contains("mikrotik") { return "router".to_string(); }

        "unknown".to_string()
    }

    /// Spawns a background task that merges OUI data from multiple sources monthly.
    /// Tries all sources — partial failures are fine, results are merged together.
    pub fn spawn_auto_updater(self: Arc<Self>) {
        tokio::spawn(async move {
            let oui_path = std::env::var("OUI_JSON")
                .unwrap_or_else(|_| "data/oui_vendors.json".to_string());

            tokio::time::sleep(Duration::from_secs(10)).await;

            loop {
                info!("Updating OUI vendor database from multiple sources...");

                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(60))
                    .user_agent("NDR-Engine/1.0")
                    .build()
                    .unwrap_or_default();

                let mut merged: HashMap<String, String> = HashMap::new();
                let mut sources_ok = 0u32;

                // ── Source 1: maclookup.app JSON ──────────────────────────────
                // Format: [{"macPrefix":"XX:XX:XX","vendorName":"..."},...]
                match client.get("https://maclookup.app/downloads/json-database/get-db").send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(text) = resp.text().await {
                            if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                                let before = merged.len();
                                for entry in &entries {
                                    let prefix = entry.get("macPrefix")
                                        .and_then(|v| v.as_str()).unwrap_or("").trim().to_uppercase();
                                    let vendor = entry.get("vendorName")
                                        .and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                                    if prefix.len() == 8 && !vendor.is_empty() {
                                        merged.entry(prefix).or_insert(vendor);
                                    }
                                }
                                info!("Source 1 (maclookup.app): +{} OUI entries", merged.len() - before);
                                sources_ok += 1;
                            }
                        }
                    }
                    _ => tracing::warn!("Source 1 (maclookup.app): unreachable"),
                }

                // ── Source 2: IEEE OUI CSV ────────────────────────────────────
                // Format: Registry,Assignment,Organization Name,...
                // Assignment is 6-char hex (no colons), e.g. "AABBCC"
                match client.get("http://standards-oui.ieee.org/oui/oui.csv").send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(text) = resp.text().await {
                            let mut rdr = csv::ReaderBuilder::new()
                                .has_headers(true)
                                .from_reader(text.as_bytes());
                            let before = merged.len();
                            for result in rdr.records().flatten() {
                                if result.len() >= 3 {
                                    let assignment = result[1].trim();
                                    let org = result[2].trim().to_string();
                                    if assignment.len() == 6 && !org.is_empty() {
                                        let prefix = format!(
                                            "{}:{}:{}",
                                            &assignment[0..2], &assignment[2..4], &assignment[4..6]
                                        ).to_uppercase();
                                        merged.entry(prefix).or_insert(org);
                                    }
                                }
                            }
                            info!("Source 2 (IEEE CSV): +{} OUI entries", merged.len() - before);
                            sources_ok += 1;
                        }
                    }
                    _ => tracing::warn!("Source 2 (IEEE CSV): unreachable"),
                }

                // ── Source 3: Wireshark manuf file ────────────────────────────
                // Format: XX:XX:XX\tShortName\tFull Organization Name
                match client.get("https://www.wireshark.org/download/automated/data/manuf").send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(text) = resp.text().await {
                            let before = merged.len();
                            for line in text.lines() {
                                let line = line.trim();
                                if line.starts_with('#') || line.is_empty() { continue; }
                                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                                if parts.len() >= 2 {
                                    let mac_field = parts[0].trim();
                                    // Only 3-byte OUIs (XX:XX:XX), skip longer entries
                                    if mac_field.len() == 8 && mac_field.chars().filter(|&c| c == ':').count() == 2 {
                                        let prefix = mac_field.to_uppercase();
                                        // Prefer the long name (parts[2]) over short name (parts[1])
                                        let vendor = if parts.len() >= 3 && !parts[2].trim().is_empty() {
                                            parts[2].trim().to_string()
                                        } else {
                                            parts[1].trim().to_string()
                                        };
                                        if !vendor.is_empty() {
                                            merged.entry(prefix).or_insert(vendor);
                                        }
                                    }
                                }
                            }
                            info!("Source 3 (Wireshark manuf): +{} OUI entries", merged.len() - before);
                            sources_ok += 1;
                        }
                    }
                    _ => tracing::warn!("Source 3 (Wireshark manuf): unreachable"),
                }

                // ── Source 4: GitHub silverwind/oui JSON ──────────────────────
                // Format: {"AABBCC": "Vendor Name",...} (no colons in key)
                match client.get("https://raw.githubusercontent.com/silverwind/oui/master/oui.json").send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(text) = resp.text().await {
                            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&text) {
                                let before = merged.len();
                                for (k, v) in map {
                                    if k.len() == 6 {
                                        let prefix = format!(
                                            "{}:{}:{}",
                                            &k[0..2], &k[2..4], &k[4..6]
                                        ).to_uppercase();
                                        merged.entry(prefix).or_insert(v);
                                    }
                                }
                                info!("Source 4 (silverwind/oui): +{} OUI entries", merged.len() - before);
                                sources_ok += 1;
                            }
                        }
                    }
                    _ => tracing::warn!("Source 4 (silverwind/oui): unreachable"),
                }

                // ── Flush merged map into live oui_map and persist ────────────
                if sources_ok > 0 {
                    info!("OUI update complete: {} total entries from {}/4 sources", merged.len(), sources_ok);
                    for (k, v) in &merged {
                        self.oui_map.insert(k.clone(), v.clone());
                    }
                    if let Ok(json_str) = serde_json::to_string(&merged) {
                        let _ = fs::create_dir_all(
                            std::path::Path::new(&oui_path).parent()
                                .unwrap_or(std::path::Path::new("."))
                        );
                        if fs::write(&oui_path, json_str).is_ok() {
                            info!("OUI database saved to {}", oui_path);
                        }
                    }
                } else {
                    tracing::warn!("All OUI sources unreachable — keeping existing database");
                }

                let sleep_secs = if sources_ok > 0 {
                    30 * 24 * 3600u64 // retry in 30 days
                } else {
                    7 * 24 * 3600u64  // retry sooner if all failed
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }
        });
    }
}
