// Canonical event model shared across ndr-engine, siem-engine, and future consumers.
// Field names inspired by Malcolm's ECS normalization (public domain, CC0).
// NDR-specific normalizers (zeek.rs, suricata.rs, linux.rs) live in ndr-engine and
// produce this type; siem-engine parsers will produce it for Windows/cloud events.
// License: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Event source tag ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSource {
    // NDR sources
    Zeek,
    Suricata,
    Linux,
    // SIEM sources (parsed by siem-engine)
    WindowsEvent,
    Syslog,
    CloudTrailAws,
    AzureAd,
    Okta,
    Unknown,
}

// ── Suricata alert sub-object ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    pub signature:        String,
    pub signature_id:     u64,
    pub category:         String,
    /// 1 = high, 2 = medium, 3 = low  (Suricata convention)
    pub severity:         u8,
    pub mitre_tactics:    Vec<String>,
    pub mitre_techniques: Vec<String>,
}

// ── Canonical normalized event ────────────────────────────────────────────
// Internal ECS-like representation shared by every detection/correlation module.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    // Network 5-tuple
    pub source_ip:        Option<String>,
    pub source_port:      Option<u16>,
    pub dest_ip:          Option<String>,
    pub dest_port:        Option<u16>,
    pub proto:            Option<String>,   // tcp / udp / icmp

    // Application layer
    pub network_protocol: Option<String>,

    // Correlation join key
    pub community_id:     Option<String>,

    // Source metadata
    pub event_source:     EventSource,
    pub log_source:       Option<String>,   // conn / dns / alert / flow …
    pub timestamp:        u64,              // Unix milliseconds

    // NDR/Zeek-specific
    pub uid:              Option<String>,
    pub conn_state:       Option<String>,

    // NDR/Suricata-specific
    pub event_type:       Option<String>,   // alert / flow / dns / http …
    pub alert:            Option<AlertInfo>,

    // Raw payload kept for dashboard & storage display
    pub raw:              Value,

    // ── Enrichment fields ─────────────────────────────────────────────────
    // Populated by the consumer BEFORE Sigma detection so rules can test
    // geo, threat-intel, and direction. Absent from wire data — default.
    #[serde(default)]
    pub is_malicious:     bool,
    #[serde(default)]
    pub src_country_code: String,
    #[serde(default)]
    pub dst_country_code: String,
    #[serde(default)]
    pub src_asn_org:      String,
    #[serde(default)]
    pub dst_asn_org:      String,
    #[serde(default)]
    pub direction:        String,  // "inbound" | "outbound" | "internal" | "unknown"
}

impl NormalizedEvent {
    /// A blank event used as the "absent" half of a correlation hit when we
    /// need to call RiskScorer without a matching counterpart event.
    pub fn blank() -> Self {
        NormalizedEvent {
            source_ip: None, source_port: None,
            dest_ip:   None, dest_port:   None,
            proto: None, network_protocol: None, community_id: None,
            event_source: EventSource::Unknown, log_source: None,
            timestamp: 0, uid: None, conn_state: None,
            event_type: None, alert: None,
            raw: Value::Null,
            is_malicious: false,
            src_country_code: String::new(), dst_country_code: String::new(),
            src_asn_org: String::new(),      dst_asn_org: String::new(),
            direction: String::new(),
        }
    }

    /// True if this event should be silently dropped before correlation.
    pub fn should_drop(&self) -> bool {
        let is_conn_log = self.log_source.as_deref()
            .map(|s| matches!(s, "conn" | "flow"))
            .unwrap_or(false);
        if is_conn_log {
            let no_src = self.source_ip.as_deref().map(|s| s.is_empty()).unwrap_or(true);
            let no_dst = self.dest_ip.as_deref().map(|s| s.is_empty()).unwrap_or(true);
            if no_src && no_dst {
                return true;
            }
        }

        if let Some(ls) = &self.log_source {
            matches!(
                ls.as_str(),
                "stats" | "capture_loss" | "analyzer" | "analyzer_debug"
                    | "broker" | "reporter" | "loaded_scripts"
                    | "packet_filter" | "cluster" | "config"
                    | "stderr" | "stdout" | "prof"
            )
        } else if let Some(et) = &self.event_type {
            matches!(et.as_str(), "stats")
        } else {
            false
        }
    }

    /// Return a field value as a String for SIGMA rule matching.
    /// Falls back to the raw JSON field if not in the canonical struct.
    pub fn get_field(&self, field: &str) -> Option<String> {
    match field {
        // ── Canonical field names ─────────────────
        "source_ip"        => self.source_ip.clone(),
        "dest_ip"          => self.dest_ip.clone(),
        "source_port"      => self.source_port.map(|p| p.to_string()),
        "dest_port"        => self.dest_port.map(|p| p.to_string()),
        "proto"            => self.proto.clone(),
        "network_protocol" => self.network_protocol.clone(),
        "community_id"     => self.community_id.clone(),
        "conn_state"       => self.conn_state.clone(),
        "event_type"       => self.event_type.clone(),
        "log_source"       => self.log_source.clone(),
        "alert.signature"  => self.alert.as_ref().map(|a| a.signature.clone()),
        "alert.category"   => self.alert.as_ref().map(|a| a.category.clone()),
        "alert.severity"   => self.alert.as_ref().map(|a| a.severity.to_string()),

        // ── Linux endpoint fields (SIGMA linux rules) ─────────────────────
        "Image"               => self.raw.get("Image").and_then(|v| v.as_str()).map(String::from),
        "CommandLine"         => self.raw.get("CommandLine").and_then(|v| v.as_str()).map(String::from),
        "ParentImage"         => self.raw.get("ParentImage").and_then(|v| v.as_str()).map(String::from),
        "ParentCommandLine"   => self.raw.get("ParentCommandLine").and_then(|v| v.as_str()).map(String::from),
        "User"                => self.raw.get("User").and_then(|v| v.as_str()).map(String::from),
        "ProcessId"           => self.raw.get("pid").and_then(|v| v.as_str()).map(String::from),
        "ParentProcessId"     => self.raw.get("ppid").and_then(|v| v.as_str()).map(String::from),
        "TargetFilename"      => self.raw.get("TargetFilename").and_then(|v| v.as_str()).map(String::from),
        "DestinationIp"       => self.dest_ip.clone()
                                    .or_else(|| self.raw.get("DestinationIp").and_then(|v| v.as_str()).map(String::from)),
        "DestinationPort"     => self.dest_port.map(|p| p.to_string())
                                    .or_else(|| self.raw.get("DestinationPort").and_then(|v| v.as_str()).map(String::from)),
        "DestinationHostname" => self.raw.get("DestinationHostname").and_then(|v| v.as_str()).map(String::from),
        "Initiated"           => self.raw.get("Initiated").and_then(|v| v.as_str()).map(String::from),
        "type"                => self.raw.get("record_type").and_then(|v| v.as_str()).map(String::from),
        "exe"                 => self.raw.get("exe").and_then(|v| v.as_str()).map(String::from),
        "comm"                => self.raw.get("comm").and_then(|v| v.as_str()).map(String::from),

        // ── Enrichment fields (populated before Sigma in consumer) ───────
        "is_malicious"      => Some(self.is_malicious.to_string()),
        "direction"         => if self.direction.is_empty() { None } else { Some(self.direction.clone()) },
        "src_country_code"
        | "src_country"     => if self.src_country_code.is_empty() { None } else { Some(self.src_country_code.clone()) },
        "dst_country_code"
        | "dst_country"     => if self.dst_country_code.is_empty() { None } else { Some(self.dst_country_code.clone()) },
        "src_asn_org"       => if self.src_asn_org.is_empty() { None } else { Some(self.src_asn_org.clone()) },
        "dst_asn_org"
        | "asn_org"         => if self.dst_asn_org.is_empty() { None } else { Some(self.dst_asn_org.clone()) },

        // ── Aliases ───────────────────────────────
        "src_ip"    => self.source_ip.clone(),
        "dst_ip"    => self.dest_ip.clone(),
        "src_port"  => self.source_port.map(|p| p.to_string()),
        "dst_port"  => self.dest_port.map(|p| p.to_string()),

        // ── Zeek raw field names (SigmaHQ community rules use these) ─────
        "id.orig_h" => self.source_ip.clone(),
        "id.resp_h" => self.dest_ip.clone(),
        "id.orig_p" => self.source_port.map(|p| p.to_string()),
        "id.resp_p" => self.dest_port.map(|p| p.to_string()),
        "source"    => Some(match self.event_source {
                          EventSource::Zeek          => "agent-z".to_string(),
                          EventSource::Suricata      => "agent-s".to_string(),
                          EventSource::Linux         => "linux".to_string(),
                          EventSource::WindowsEvent  => "windows".to_string(),
                          EventSource::Syslog        => "syslog".to_string(),
                          EventSource::CloudTrailAws => "aws-cloudtrail".to_string(),
                          EventSource::AzureAd       => "azure-ad".to_string(),
                          EventSource::Okta          => "okta".to_string(),
                          EventSource::Unknown       => "unknown".to_string(),
                       }),

        // ── Fallback to raw JSON with dot-path traversal ─────────────────
        _ => {
            if let Some(v) = self.raw.get(field).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            let parts: Vec<&str> = field.split('.').collect();
            if parts.len() > 1 {
                let mut cur = &self.raw;
                for part in &parts {
                    match cur.get(*part) {
                        Some(v) => cur = v,
                        None    => return None,
                    }
                }
                return cur.as_str().map(String::from)
                    .or_else(|| if cur.is_null() { None } else { Some(cur.to_string()) });
            }
            None
        }
    }
}
}
