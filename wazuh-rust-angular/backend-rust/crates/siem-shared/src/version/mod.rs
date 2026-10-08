//! Wazuh Version & SemVer Engine (version_op.c)
//!
//! Provides parsing, semantic version comparison, and compatibility matrices
//! for Wazuh manager and agent versions.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::sync::LazyLock;

static VERSION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:Wazuh\s+)?v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([a-zA-Z0-9.\-_]+))?$").unwrap()
});

/// A parsed Wazuh semantic version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WazuhVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
}

impl WazuhVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
        }
    }

    /// Parse a version string like "v4.14.7", "Wazuh v4.2.0-rc1", or "4.9".
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        let caps = VERSION_REGEX
            .captures(trimmed)
            .ok_or_else(|| format!("Invalid Wazuh version string: '{}'", s))?;

        let major = caps[1]
            .parse::<u32>()
            .map_err(|e| format!("Invalid major version: {}", e))?;
        let minor = caps[2]
            .parse::<u32>()
            .map_err(|e| format!("Invalid minor version: {}", e))?;
        let patch = caps
            .get(3)
            .map(|m| m.as_str().parse::<u32>().unwrap_or(0))
            .unwrap_or(0);
        let pre_release = caps.get(4).map(|m| m.as_str().to_string());

        Ok(Self {
            major,
            minor,
            patch,
            pre_release,
        })
    }

    /// Check if this agent version is compatible with a manager version.
    /// Wazuh rule: Manager can support agents that are at most the manager's version
    /// (Manager >= Agent).
    pub fn is_compatible_with_manager(&self, manager_version: &WazuhVersion) -> bool {
        // Agent must not be newer than manager
        self <= manager_version
    }
}

impl PartialOrd for WazuhVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WazuhVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => match self.patch.cmp(&other.patch) {
                    Ordering::Equal => match (&self.pre_release, &other.pre_release) {
                        (None, None) => Ordering::Equal,
                        (Some(_), None) => Ordering::Less, // release is higher than pre-release
                        (None, Some(_)) => Ordering::Greater,
                        (Some(a), Some(b)) => a.cmp(b),
                    },
                    ord => ord,
                },
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl fmt::Display for WazuhVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref pre) = self.pre_release {
            write!(f, "v{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}
