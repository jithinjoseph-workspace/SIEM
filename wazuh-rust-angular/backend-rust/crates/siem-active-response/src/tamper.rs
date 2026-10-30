//! Agent tamper protection (EDR, not in Wazuh): what `tamper-protect` writes on the
//! agent service. Locked, the "WazuhSvc" service lets Administrators read and start it
//! but not stop, pause, reconfigure, delete it or change who may; SYSTEM (the agent
//! itself: upgrades, restarts) keeps full control. Its recovery restarts a killed agent.
//! The descriptor found before the first lock is kept, so unlocking restores it exactly.
//! An administrator can still take the service over (owner, registry): this makes it
//! slow and loud, the console's alerts (siem-api tamper.rs) make it visible.

pub const SERVICE: &str = "WazuhSvc";
/// SYSTEM: everything; Administrators: query, start, interrogate, user control, read;
/// interactive and service users: query and read (the Windows default for them).
pub const LOCKED_SDDL: &str = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
/// The SCM default, when no earlier descriptor was saved.
pub const DEFAULT_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
/// Recovery: restart after 5 s, 10 s, then every minute; counters reset after a day.
pub const FAILURE_ARGS: [&str; 6] = ["failure", SERVICE, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/60000"];

/// The SDDL line of `sc sdshow` output.
pub fn sddl_of(sdshow: &str) -> Option<String> {
    sdshow.lines().map(str::trim).find(|l| l.starts_with("D:") || l.starts_with("O:") || l.starts_with("G:")).map(String::from)
}

/// What `tamper.state` keeps: the descriptor to restore, the maintenance window open now.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct State {
    pub original: Option<String>,
    pub window: Option<String>,
}

impl State {
    pub fn parse(t: &str) -> State {
        let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string())).filter(|v| !v.is_empty());
        State { original: get("original="), window: get("window=") }
    }

    pub fn render(&self) -> String {
        format!("original={}\nwindow={}\n", self.original.as_deref().unwrap_or(""), self.window.as_deref().unwrap_or(""))
    }

    /// The descriptor an unlock restores: the saved one, else the Windows default
    /// (never our own locked one, which a crash between lock and save could leave behind).
    pub fn restore_sddl(&self) -> &str {
        self.original.as_deref().filter(|s| *s != LOCKED_SDDL && s.starts_with("D:")).unwrap_or(DEFAULT_SDDL)
    }
}

/// A maintenance window id: the manager's hex string.
pub fn valid_window(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_descriptor_keeps_admins_out() {
        let ace = |who: &str| LOCKED_SDDL.split(')').find(|a| a.ends_with(&format!(";;;{who}"))).unwrap().to_string();
        // WP stop, DT pause, DC change config, SD delete, WD / WO change who may
        for right in ["WP", "DT", "DC", "SD", "WD", "WO"] {
            assert!(!ace("BA").contains(right), "Administrators must not have {right}");
            assert!(ace("SY").contains(right), "SYSTEM keeps {right}");
        }
        assert!(ace("BA").contains("RP"), "Administrators may still start it");
    }

    #[test]
    fn state_and_sdshow() {
        let out = "\r\nD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\r\n\r\n";
        assert_eq!(sddl_of(out).as_deref(), Some("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"));
        assert_eq!(sddl_of("[SC] OpenService FAILED 1060"), None);
        let s = State { original: Some("D:(A;;CC;;;BA)".into()), window: Some("ab12".into()) };
        assert_eq!(State::parse(&s.render()), s);
        assert_eq!(State::parse("").restore_sddl(), DEFAULT_SDDL);
        assert_eq!(State { original: Some(LOCKED_SDDL.into()), window: None }.restore_sddl(), DEFAULT_SDDL);
        assert!(valid_window("00ff") && !valid_window("a b"));
    }
}
