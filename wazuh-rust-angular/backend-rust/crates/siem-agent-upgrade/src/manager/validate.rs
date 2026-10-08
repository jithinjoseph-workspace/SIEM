use std::cmp::Ordering;
use sha1::{Sha1, Digest};

pub const WM_UPGRADE_MINIMAL_VERSION_SUPPORT: &str = "v3.0.0";
pub const WM_UPGRADE_MINIMAL_VERSION_SUPPORT_MACOS: &str = "v4.3.0";
pub const WM_UPGRADE_NEW_LINUX_VERSION_REPOSITORY: &str = "v3.4.0";
pub const WM_UPGRADE_NEW_VERSION_STRUCTURE_REPOSITORY: &str = "v4.9.0";
pub const WM_UPGRADE_NEW_UPGRADE_MECHANISM: &str = "v4.1.0";
pub const WM_UPGRADE_WPK_DEFAULT_PATH: &str = "var/upgrade/";
pub const MANAGER_ID: u32 = 0;

pub static INVALID_PLATFORMS: &[&str] = &[
    "solaris", "sunos", "aix", "hp-ux", "bsd",
];

pub static ROLLING_PLATFORMS: &[&str] = &[
    "opensuse-tumbleweed", "arch",
];

pub static DEB_PLATFORMS: &[&str] = &[
    "debian", "ubuntu",
];

pub static RPM_PLATFORMS: &[&str] = &[
    "amzn", "centos", "fedora", "ol", "opensuse", "opensuse-leap",
    "opensuse-tumbleweed", "rhel", "sles", "suse", "rocky", "almalinux",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeErrorCode {
    Success = 0,
    ParsingError = 1,
    ParsingRequiredParameter = 2,
    TaskConfigurations = 3,
    TaskManagerCommunication = 4,
    TaskManagerFailure = 5,
    GlobalDbFailure = 6,
    InvalidActionForManager = 7,
    AgentIsNotActive = 8,
    SystemNotSupported = 9,
    UpgradeAlreadyInProgress = 10,
    NotMinimalVersionSupported = 11,
    NewVersionLeesOrEqualThatCurrent = 12,
    NewVersionGreaterMaster = 13,
    UrlNotFound = 14,
    WpkVersionDoesNotExist = 15,
    WpkFileDoesNotExist = 16,
    WpkSha1DoesNotMatch = 17,
    SendLockRestartError = 18,
    SendOpenError = 19,
    SendWriteError = 20,
    SendCloseError = 21,
    SendSha1Error = 22,
    SendUpgradeError = 23,
    UpgradeError = 24,
    UpgradeErrorMissingPackage = 25,
    UnknownError = 26,
}

impl UpgradeErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::ParsingError => "Could not parse message JSON",
            Self::ParsingRequiredParameter => "Required parameters in json message where not found",
            Self::TaskConfigurations => "JSON parameter not recognized",
            Self::TaskManagerCommunication => "Task manager communication error",
            Self::TaskManagerFailure => "",
            Self::GlobalDbFailure => "Agent information not found in database",
            Self::InvalidActionForManager => "Action not available for Manager (agent 000)",
            Self::AgentIsNotActive => "Agent is not active",
            Self::SystemNotSupported => "The WPK for this platform is not available",
            Self::UpgradeAlreadyInProgress => "Upgrade procedure could not start. Agent already upgrading",
            Self::NotMinimalVersionSupported => "Remote upgrade is not available for this agent version",
            Self::NewVersionLeesOrEqualThatCurrent => "Current agent version is greater or equal",
            Self::NewVersionGreaterMaster => "Upgrading an agent to a version higher than the manager requires the force flag",
            Self::UrlNotFound => "The repository is not reachable",
            Self::WpkVersionDoesNotExist => "The version of the WPK does not exist in the repository",
            Self::WpkFileDoesNotExist => "The WPK file does not exist",
            Self::WpkSha1DoesNotMatch => "The WPK sha1 of the file is not valid",
            Self::SendLockRestartError => "Send lock restart error",
            Self::SendOpenError => "Send open file error",
            Self::SendWriteError => "Send write file error",
            Self::SendCloseError => "Send close file error",
            Self::SendSha1Error => "Send verify sha1 error",
            Self::SendUpgradeError => "Send upgrade command error",
            Self::UpgradeError => "Upgrade procedure exited with error code",
            Self::UpgradeErrorMissingPackage => "Upgrade procedure exited with error code, missing dependency in agent",
            Self::UnknownError => "Upgrade procedure could not start",
        }
    }
}

/// Validates agent ID (Agent 0 is manager and cannot be upgraded)
pub fn validate_id(agent_id: u32) -> Result<(), UpgradeErrorCode> {
    if agent_id == MANAGER_ID {
        Err(UpgradeErrorCode::InvalidActionForManager)
    } else {
        Ok(())
    }
}

/// Validates agent connection status (must be "active")
pub fn validate_status(connection_status: &str) -> Result<(), UpgradeErrorCode> {
    if connection_status.eq_ignore_ascii_case("active") {
        Ok(())
    } else {
        Err(UpgradeErrorCode::AgentIsNotActive)
    }
}

/// Validates agent platform and deduces the package type (.deb, .rpm, .msi, .pkg)
pub fn validate_system(
    platform: &str,
    os_major: Option<&str>,
    os_minor: Option<&str>,
    arch: Option<&str>,
) -> Result<String, UpgradeErrorCode> {
    // Check blacklisted platforms
    if INVALID_PLATFORMS.iter().any(|&p| p.eq_ignore_ascii_case(platform)) {
        return Err(UpgradeErrorCode::SystemNotSupported);
    }

    if platform.eq_ignore_ascii_case("windows") {
        return Ok("msi".to_string());
    }

    if platform.eq_ignore_ascii_case("darwin") {
        if arch.is_some() {
            return Ok("pkg".to_string());
        } else {
            return Err(UpgradeErrorCode::SystemNotSupported);
        }
    }

    if arch.is_none() {
        return Err(UpgradeErrorCode::SystemNotSupported);
    }

    // Linux checks
    let is_rolling = ROLLING_PLATFORMS.iter().any(|&p| p.eq_ignore_ascii_case(platform));
    if !is_rolling {
        if let Some(major) = os_major {
            if !platform.eq_ignore_ascii_case("ubuntu") || os_minor.is_some() {
                // Unsupported linux releases
                if (platform.eq_ignore_ascii_case("sles") && major == "11")
                    || (platform.eq_ignore_ascii_case("suse") && major == "11")
                    || (platform.eq_ignore_ascii_case("ol") && major == "5")
                    || (platform.eq_ignore_ascii_case("rhel") && major == "5")
                    || (platform.eq_ignore_ascii_case("centos") && major == "5")
                {
                    return Err(UpgradeErrorCode::SystemNotSupported);
                }
            }
        }
    }

    if DEB_PLATFORMS.iter().any(|&p| p.eq_ignore_ascii_case(platform)) {
        return Ok("deb".to_string());
    }

    if RPM_PLATFORMS.iter().any(|&p| p.eq_ignore_ascii_case(platform)) {
        return Ok("rpm".to_string());
    }

    Err(UpgradeErrorCode::SystemNotSupported)
}

/// Translates architecture names according to packaging conventions
pub fn translate_arch(platform: &str, package_type: &str, arch: &str) -> String {
    if arch == "x86_64" {
        if platform.eq_ignore_ascii_case("darwin") && package_type == "pkg" {
            return "intel64".to_string();
        } else if package_type == "deb" {
            return "amd64".to_string();
        }
    } else if arch == "aarch64" {
        if platform.eq_ignore_ascii_case("darwin") && package_type == "pkg" {
            return "arm64".to_string();
        } else if package_type == "deb" {
            return "arm64".to_string();
        }
    }
    arch.to_string()
}

/// Semver comparator matching Wazuh compare_wazuh_versions
pub fn compare_wazuh_versions(v1: &str, v2: &str) -> Ordering {
    let parse_ver = |v: &str| -> Vec<u32> {
        let trimmed = v.trim().trim_start_matches('v');
        trimmed
            .split('.')
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect()
    };

    let parts1 = parse_ver(v1);
    let parts2 = parse_ver(v2);

    for (p1, p2) in parts1.iter().zip(parts2.iter()) {
        match p1.cmp(p2) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    parts1.len().cmp(&parts2.len())
}

/// Validates version constraints:
/// 1. Agent version >= v3.0.0 (or v4.3.0 for macOS)
/// 2. Target version > agent version (unless force_upgrade)
/// 3. Target version <= manager version (unless force_upgrade)
pub fn validate_version(
    wazuh_version: &str,
    platform: &str,
    target_version: &str,
    manager_version: &str,
    force_upgrade: bool,
) -> Result<(), UpgradeErrorCode> {
    if compare_wazuh_versions(wazuh_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT) == Ordering::Less {
        return Err(UpgradeErrorCode::NotMinimalVersionSupported);
    }

    if platform.eq_ignore_ascii_case("darwin")
        && compare_wazuh_versions(wazuh_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT_MACOS) == Ordering::Less
    {
        return Err(UpgradeErrorCode::NotMinimalVersionSupported);
    }

    if !force_upgrade {
        if compare_wazuh_versions(wazuh_version, target_version) != Ordering::Less {
            return Err(UpgradeErrorCode::NewVersionLeesOrEqualThatCurrent);
        }
        if compare_wazuh_versions(target_version, manager_version) == Ordering::Greater {
            return Err(UpgradeErrorCode::NewVersionGreaterMaster);
        }
    }

    Ok(())
}

/// Constructs the repository path and WPK filename for an agent
pub fn build_wpk_file_spec(
    wpk_repository: &str,
    wpk_version: &str,
    platform: &str,
    package_type: &str,
    arch: &str,
    major_version: Option<&str>,
    minor_version: Option<&str>,
) -> (String, String) {
    let mut base_repo = wpk_repository.trim_end_matches('/').to_string();
    if !base_repo.starts_with("http://") && !base_repo.starts_with("https://") {
        base_repo = format!("https://{base_repo}");
    }
    base_repo.push('/');

    if platform.eq_ignore_ascii_case("windows") {
        let path = format!("{base_repo}windows/");
        let file = format!("wazuh_agent_{wpk_version}_windows.wpk");
        (path, file)
    } else if platform.eq_ignore_ascii_case("darwin") {
        let pkg_arch = translate_arch(platform, package_type, arch);
        if compare_wazuh_versions(wpk_version, WM_UPGRADE_NEW_VERSION_STRUCTURE_REPOSITORY) != Ordering::Less {
            let path = format!("{base_repo}macos/{package_type}/{pkg_arch}/");
            let file = format!("wazuh_agent_{wpk_version}_macos_{pkg_arch}.{package_type}.wpk");
            (path, file)
        } else {
            let path = format!("{base_repo}macos/{arch}/{package_type}/");
            let file = format!("wazuh_agent_{wpk_version}_macos_{arch}.wpk");
            (path, file)
        }
    } else {
        // Linux
        let pkg_arch = translate_arch(platform, package_type, arch);
        if compare_wazuh_versions(wpk_version, WM_UPGRADE_NEW_VERSION_STRUCTURE_REPOSITORY) != Ordering::Less {
            let path = format!("{base_repo}linux/{package_type}/{pkg_arch}/");
            let file = format!("wazuh_agent_{wpk_version}_linux_{pkg_arch}.{package_type}.wpk");
            (path, file)
        } else if compare_wazuh_versions(wpk_version, WM_UPGRADE_NEW_LINUX_VERSION_REPOSITORY) != Ordering::Less {
            let path = format!("{base_repo}linux/{arch}/");
            let file = format!("wazuh_agent_{wpk_version}_linux_{arch}.wpk");
            (path, file)
        } else if platform.eq_ignore_ascii_case("ubuntu") {
            let maj = major_version.unwrap_or("0");
            let min = minor_version.unwrap_or("0");
            let path = format!("{base_repo}ubuntu/{maj}.{min}/{arch}/");
            let file = format!("wazuh_agent_{wpk_version}_ubuntu_{maj}.{min}_{arch}.wpk");
            (path, file)
        } else {
            let maj = major_version.unwrap_or("0");
            let path = format!("{base_repo}{platform}/{maj}/{arch}/");
            let file = format!("wazuh_agent_{wpk_version}_{platform}_{maj}_{arch}.wpk");
            (path, file)
        }
    }
}

/// Parses versions file content (lines of "<version> <sha1>") to find matching hash
pub fn parse_versions_content(content: &str, target_version: &str) -> Option<String> {
    for line in content.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() >= 2 {
            let ver = parts[0];
            let sha1 = parts[1];
            if compare_wazuh_versions(ver, target_version) == Ordering::Equal {
                return Some(sha1.to_string());
            }
        }
    }
    None
}

/// Verifies SHA-1 digest of binary data
pub fn verify_sha1(data: &[u8], expected_sha1: &str) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let computed_hex = hex::encode(result);
    computed_hex.eq_ignore_ascii_case(expected_sha1.trim())
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
