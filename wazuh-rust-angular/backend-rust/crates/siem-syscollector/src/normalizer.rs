use crate::tables::PackageItem;
use regex::Regex;

/// Syscollector Normalizer ported from Wazuh syscollectorNormalizer.cpp and norm_config.json.
pub struct SysNormalizer {
    exclusions: Vec<Regex>,
    vendor_rules: Vec<(Regex, &'static str)>,
}

impl Default for SysNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SysNormalizer {
    pub fn new() -> Self {
        let exclusions = vec![
            Regex::new(r"(?i)^(Siri|iCloud|QuickTime.*)$").unwrap(),
        ];

        let vendor_rules = vec![
            (Regex::new(r"(?i).*Canonical.*").unwrap(), "canonical"),
            (Regex::new(r"(?i).*(Red\s*Hat|RedHat|CentOS).*").unwrap(), "redhat"),
            (Regex::new(r"(?i).*Debian.*").unwrap(), "debian"),
            (Regex::new(r"(?i).*Microsoft.*").unwrap(), "microsoft"),
            (Regex::new(r"(?i).*VMware.*").unwrap(), "vmware"),
            (Regex::new(r"(?i).*Oracle.*").unwrap(), "oracle"),
            (Regex::new(r"(?i).*SUSE.*").unwrap(), "suse"),
            (Regex::new(r"(?i).*Amazon.*").unwrap(), "amazon"),
        ];

        Self {
            exclusions,
            vendor_rules,
        }
    }

    /// Check if a package should be excluded from inventory.
    pub fn is_excluded(&self, package_name: &str) -> bool {
        self.exclusions.iter().any(|re| re.is_match(package_name))
    }

    /// Canonicalize architecture string across diverse packaging systems.
    pub fn normalize_arch(arch: &str) -> &'static str {
        match arch.to_ascii_lowercase().as_str() {
            "amd64" | "x86_64" | "x64" => "x86_64",
            "i386" | "i686" | "x86" => "x86",
            "arm64" | "aarch64" => "arm64",
            "armhf" | "armv7l" => "armhf",
            "noarch" | "all" => "all",
            _ => "unknown",
        }
    }

    /// Normalize vendor string based on dictionary patterns.
    pub fn normalize_vendor(&self, vendor_str: &str) -> String {
        for (pattern, canonical) in &self.vendor_rules {
            if pattern.is_match(vendor_str) {
                return (*canonical).to_string();
            }
        }
        vendor_str.to_lowercase()
    }

    /// Normalize an entire PackageItem in-place.
    pub fn normalize_package(&self, pkg: &mut PackageItem) {
        pkg.architecture = Self::normalize_arch(&pkg.architecture).to_string();
        if let Some(v) = &pkg.vendor {
            pkg.vendor = Some(self.normalize_vendor(v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_normalization() {
        assert_eq!(SysNormalizer::normalize_arch("amd64"), "x86_64");
        assert_eq!(SysNormalizer::normalize_arch("x86_64"), "x86_64");
        assert_eq!(SysNormalizer::normalize_arch("x64"), "x86_64");
        assert_eq!(SysNormalizer::normalize_arch("i386"), "x86");
        assert_eq!(SysNormalizer::normalize_arch("aarch64"), "arm64");
        assert_eq!(SysNormalizer::normalize_arch("noarch"), "all");
    }

    #[test]
    fn test_vendor_normalization() {
        let norm = SysNormalizer::new();
        assert_eq!(
            norm.normalize_vendor("Debian Samba Maintainers <pkg-samba-maint@lists.alioth.debian.org>"),
            "debian"
        );
        assert_eq!(
            norm.normalize_vendor("Canonical Ltd. <support@canonical.com>"),
            "canonical"
        );
        assert_eq!(
            norm.normalize_vendor("Red Hat, Inc. / Fedora Project"),
            "redhat"
        );
        assert_eq!(
            norm.normalize_vendor("Microsoft Corporation"),
            "microsoft"
        );
    }

    #[test]
    fn test_exclusions() {
        let norm = SysNormalizer::new();
        assert!(norm.is_excluded("Siri"));
        assert!(norm.is_excluded("iCloud"));
        assert!(!norm.is_excluded("openssh-server"));
    }
}
