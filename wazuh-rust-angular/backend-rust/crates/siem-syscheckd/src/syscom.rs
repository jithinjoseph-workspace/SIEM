use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscomCommand {
    CheckNow,
    Restart,
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscheckStatus {
    pub is_scanning: bool,
    pub last_scan_time: Option<i64>,
    pub files_monitored: usize,
    pub registry_entries_monitored: usize,
}

pub struct SyscomHandler;

impl SyscomHandler {
    /// Parses an incoming syscheck command
    pub fn parse_command(raw: &str) -> Option<SyscomCommand> {
        let trimmed = raw.trim();
        if trimmed.contains("check_now") {
            Some(SyscomCommand::CheckNow)
        } else if trimmed.contains("restart") {
            Some(SyscomCommand::Restart)
        } else if trimmed.contains("status") {
            Some(SyscomCommand::Status)
        } else {
            None
        }
    }
}
