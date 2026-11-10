pub const FEATURE_NDR:          &str = "ndr";
pub const FEATURE_SIEM:         &str = "siem";
pub const FEATURE_SOAR:         &str = "soar";
pub const FEATURE_THREAT_INTEL: &str = "threat_intel";
pub const FEATURE_AI:           &str = "ai";

/// Lightweight tenant descriptor loaded from ClickHouse.
///
/// `features` is a comma-separated string, e.g. "ndr,siem,soar,threat_intel,ai".
/// Use [`has_feature`] to test membership rather than splitting manually.
#[derive(Debug, Clone, Default)]
pub struct Tenant {
    pub id:       String,
    pub name:     String,
    pub plan:     String,
    pub features: String,
    pub active:   bool,
}

impl Tenant {
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features
            .split(',')
            .any(|f| f.trim().eq_ignore_ascii_case(feature))
    }

    #[inline] pub fn has_ndr(&self)          -> bool { self.has_feature(FEATURE_NDR) }
    #[inline] pub fn has_siem(&self)         -> bool { self.has_feature(FEATURE_SIEM) }
    #[inline] pub fn has_soar(&self)         -> bool { self.has_feature(FEATURE_SOAR) }
    #[inline] pub fn has_threat_intel(&self) -> bool { self.has_feature(FEATURE_THREAT_INTEL) }
    #[inline] pub fn has_ai(&self)           -> bool { self.has_feature(FEATURE_AI) }
}
