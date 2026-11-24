//! The product modules a client may use (its licence, or its settings where no licence is
//! installed), as the sign-in token carries them in `features`. One rule for every server:
//! super admins may use everything, and a client whose list is empty (never set up) is not
//! limited, so no client loses a module because nobody filled the list in.

pub const SIEM: &str = "siem";
pub const NDR: &str = "ndr";
pub const SOAR: &str = "soar";
pub const THREAT_INTEL: &str = "threat_intel";
pub const AI: &str = "ai";

/// Whether a caller with this role and these features may use `module`.
pub fn allows(role: &str, features: &[String], module: &str) -> bool {
    role == "super_admin" || features.is_empty() || features.iter().any(|f| f.trim() == module)
}

/// Whether a client with these features (no role: background work for the client) has `module`.
pub fn client_has(features: &[String], module: &str) -> bool {
    features.is_empty() || features.iter().any(|f| f.trim() == module)
}

/// The answer a server gives when a module is not in the client's licence (HTTP 403).
pub fn refusal(module: &str) -> String {
    let name = match module {
        SIEM => "SIEM",
        NDR => "NDR",
        SOAR => "SOAR",
        THREAT_INTEL => "Threat Intelligence",
        AI => "AI",
        other => other,
    };
    serde_json::json!({ "status": "error", "code": "MODULE_NOT_LICENSED", "module": module,
        "message": format!("{name} is not part of this organisation's licence") }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_rule() {
        assert!(allows("analyst", &f(&["siem", "soar"]), SOAR));
        assert!(!allows("analyst", &f(&["siem", "soar"]), NDR));
        assert!(!allows("tenant_admin", &f(&["ndr"]), SIEM));
        assert!(allows("super_admin", &f(&["ndr"]), SIEM), "super admins use everything");
        assert!(allows("analyst", &[], NDR), "an empty list (never set up) does not limit");
        assert!(allows("analyst", &f(&[" ndr "]), NDR), "spaces from a comma list are ignored");
        assert!(client_has(&f(&["siem", "ai"]), AI) && !client_has(&f(&["siem"]), AI));
        assert!(refusal(NDR).contains("MODULE_NOT_LICENSED") && refusal(NDR).contains("NDR is not part"));
    }
}
