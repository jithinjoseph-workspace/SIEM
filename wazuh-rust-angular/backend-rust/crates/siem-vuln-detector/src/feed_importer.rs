use crate::cve_model::{CveVulnerability, CvssScore, Severity};
use crate::feed_database::VulnerabilityFeed;
use serde::{Deserialize, Serialize};

/// Wazuh / NVD compatible JSON Feed item representation.
/// Ported from Wazuh databaseFeedManager/eventDecoder.hpp and feedIndexer.hpp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFeedEntry {
    pub cve_id: String,
    pub package_name: String,
    pub version_constraint: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// JSON Feed bundle wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFeedBundle {
    pub version: String,
    pub vendor: Option<String>,
    pub vulnerabilities: Vec<JsonFeedEntry>,
}

/// Dynamic feed importer for Wazuh and NVD JSON feeds.
pub struct FeedImporter;

impl FeedImporter {
    /// Ingest a raw JSON string into an existing VulnerabilityFeed.
    pub fn import_json(feed: &mut VulnerabilityFeed, json_str: &str) -> Result<usize, String> {
        let bundle: JsonFeedBundle = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse CVE JSON feed: {}", e))?;

        let count = bundle.vulnerabilities.len();
        for item in bundle.vulnerabilities {
            let severity = Severity::from_str_loose(&item.severity);

            let cvss = item.cvss_score.map(|score| CvssScore {
                score,
                vector: item.cvss_vector,
                version: "3.1".to_string(),
            });

            let vuln = CveVulnerability {
                cve_id: item.cve_id,
                package_name: item.package_name,
                affected_version_range: item.version_constraint,
                fixed_version: item.fixed_version,
                severity,
                cvss,
                title: item.title.unwrap_or_default(),
                description: item.description.unwrap_or_default(),
                references: item.references,
                mitre_technique: None,
            };

            feed.add_cve(vuln);
        }

        Ok(count)
    }
}
