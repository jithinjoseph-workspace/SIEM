//! Group Validation & Sanitation (`src/os_auth/auth.c`)
//!
//! Validates agent centralized multigroup configuration and deduplicates group names.

use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

pub const MAX_GROUPS_PER_MULTIGROUP: usize = 256;
pub const MULTIGROUP_SEPARATOR: char = ',';

static GROUP_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_group_regex() -> &'static Regex {
    GROUP_REGEX.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_\.\-]+$").expect("valid group regex"))
}

/// Deduplicates comma-separated group list while preserving original ordering.
pub fn delete_repeated_groups(groups: &str) -> String {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for group in groups.split(MULTIGROUP_SEPARATOR) {
        let trimmed = group.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            unique.push(trimmed);
        }
    }

    unique.join(",")
}

/// Validates group name(s) according to Wazuh `w_auth_validate_groups` rules.
pub fn validate_groups(groups: &str) -> Result<String, String> {
    let regex = get_group_regex();
    let mut count = 0;
    let mut valid_groups = Vec::new();
    let mut seen = HashSet::new();

    for group in groups.split(MULTIGROUP_SEPARATOR) {
        let trimmed = group.trim();
        if trimmed.is_empty() {
            continue;
        }

        count += 1;
        if count > MAX_GROUPS_PER_MULTIGROUP {
            return Err(format!(
                "ERROR: Maximum multigroup reached: Limit is {}",
                MAX_GROUPS_PER_MULTIGROUP
            ));
        }

        if !regex.is_match(trimmed) {
            return Err(format!(
                "ERROR: Invalid group name: {}. Group contains forbidden characters",
                trimmed
            ));
        }

        if trimmed == "." || trimmed == ".." {
            return Err(format!(
                "ERROR: Invalid group name: {}. Directory reference not allowed",
                trimmed
            ));
        }

        if seen.insert(trimmed.to_string()) {
            valid_groups.push(trimmed);
        }
    }

    if valid_groups.is_empty() {
        return Err("ERROR: Group name cannot be empty".to_string());
    }

    Ok(valid_groups.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_groups() {
        let res = validate_groups("default,dmz_servers,web-01").unwrap();
        assert_eq!(res, "default,dmz_servers,web-01");
    }

    #[test]
    fn test_deduplicate_groups() {
        let res = validate_groups("default,web,default,db,web").unwrap();
        assert_eq!(res, "default,web,db");
    }

    #[test]
    fn test_invalid_characters() {
        assert!(validate_groups("group$1").is_err());
        assert!(validate_groups("group/subgroup").is_err());
        assert!(validate_groups("group;rm -rf").is_err());
    }

    #[test]
    fn test_directory_traversal() {
        assert!(validate_groups(".").is_err());
        assert!(validate_groups("..").is_err());
        assert!(validate_groups("default,..").is_err());
    }

    #[test]
    fn test_max_multigroups() {
        let groups: Vec<String> = (0..257).map(|i| format!("g{}", i)).collect();
        let joined = groups.join(",");
        assert!(validate_groups(&joined).is_err());
    }
}
