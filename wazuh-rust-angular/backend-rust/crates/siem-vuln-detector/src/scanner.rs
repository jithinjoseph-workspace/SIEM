use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use chrono::Utc;

use crate::cve_model::{DetectionStatus, PackageInfo, Severity, VulnerabilityDetection};
use crate::feed_database::VulnerabilityFeed;
use crate::version_matcher::matches_version_range;

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub min_severity: Severity,
    pub ignored_cves: HashSet<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Low,
            ignored_cves: HashSet::new(),
        }
    }
}

pub struct VulnerabilityScanner {
    feed: Arc<RwLock<VulnerabilityFeed>>,
    config: ScannerConfig,
}

impl VulnerabilityScanner {
    pub fn new(feed: Arc<RwLock<VulnerabilityFeed>>, config: ScannerConfig) -> Self {
        Self { feed, config }
    }

    pub fn with_default_feed() -> Self {
        Self {
            feed: Arc::new(RwLock::new(VulnerabilityFeed::new_with_builtin_feed())),
            config: ScannerConfig::default(),
        }
    }

    /// Dynamically import an external CVE JSON feed into the active scanner database
    pub fn import_feed_json(&self, json_str: &str) -> Result<usize, String> {
        let mut feed_guard = self.feed.write().map_err(|e| e.to_string())?;
        crate::feed_importer::FeedImporter::import_json(&mut feed_guard, json_str)
    }

    pub fn total_cves(&self) -> usize {
        self.feed.read().map(|f| f.total_cves()).unwrap_or(0)
    }

    /// Scan a single package for an agent
    pub fn scan_package(
        &self,
        pkg: &PackageInfo,
        agent_id: &str,
        agent_name: &str,
    ) -> Vec<VulnerabilityDetection> {
        let mut detections = Vec::new();

        let feed_guard = match self.feed.read() {
            Ok(g) => g,
            Err(_) => return detections,
        };

        if let Some(cves) = feed_guard.find_by_package(&pkg.name) {
            for cve in cves {
                // Check if CVE is ignored
                if self.config.ignored_cves.contains(&cve.cve_id) {
                    continue;
                }

                // Check severity threshold
                if cve.severity < self.config.min_severity {
                    continue;
                }

                // Perform version match against affected version range
                if matches_version_range(&pkg.version, &cve.affected_version_range) {
                    let detection_id = format!(
                        "vuln-{}-{}-{}",
                        agent_id,
                        pkg.name.to_lowercase(),
                        cve.cve_id.to_lowercase()
                    );

                    detections.push(VulnerabilityDetection {
                        id: detection_id,
                        agent_id: agent_id.to_string(),
                        agent_name: agent_name.to_string(),
                        package_name: pkg.name.clone(),
                        installed_version: pkg.version.clone(),
                        cve_id: cve.cve_id.clone(),
                        title: cve.title.clone(),
                        description: cve.description.clone(),
                        severity: cve.severity,
                        cvss_score: cve.cvss.as_ref().map(|c| c.score),
                        fixed_version: cve.fixed_version.clone(),
                        mitre_technique: cve.mitre_technique.clone(),
                        detected_at: Utc::now().to_rfc3339(),
                        status: DetectionStatus::Active,
                    });
                }
            }
        }

        detections
    }

    /// Scan the entire package inventory of an agent
    pub fn scan_inventory(
        &self,
        packages: &[PackageInfo],
        agent_id: &str,
        agent_name: &str,
    ) -> Vec<VulnerabilityDetection> {
        let mut all_detections = Vec::new();
        for pkg in packages {
            let matches = self.scan_package(pkg, agent_id, agent_name);
            all_detections.extend(matches);
        }
        all_detections
    }

    /// Compare previous scan detections with current scan detections to compute state transitions:
    /// (new_detections, resolved_detections)
    pub fn diff_scans(
        previous: &[VulnerabilityDetection],
        current: &[VulnerabilityDetection],
    ) -> (Vec<VulnerabilityDetection>, Vec<VulnerabilityDetection>) {
        let mut prev_map: HashMap<&str, &VulnerabilityDetection> = HashMap::new();
        for d in previous {
            if d.status == DetectionStatus::Active {
                prev_map.insert(&d.id, d);
            }
        }

        let mut curr_map: HashMap<&str, &VulnerabilityDetection> = HashMap::new();
        for d in current {
            curr_map.insert(&d.id, d);
        }

        // New detections are in current but not in previous
        let mut new_detections = Vec::new();
        for (id, d) in &curr_map {
            if !prev_map.contains_key(*id) {
                new_detections.push((*d).clone());
            }
        }

        // Resolved detections were in previous but no longer present in current
        let mut resolved_detections = Vec::new();
        for (id, prev_d) in &prev_map {
            if !curr_map.contains_key(*id) {
                let mut resolved = (*prev_d).clone();
                resolved.status = DetectionStatus::Resolved;
                resolved_detections.push(resolved);
            }
        }

        (new_detections, resolved_detections)
    }
}
