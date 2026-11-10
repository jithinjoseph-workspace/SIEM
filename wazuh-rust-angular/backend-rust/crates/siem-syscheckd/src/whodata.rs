use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WhodataInfo {
    pub user_name: Option<String>,
    pub user_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub parent_name: Option<String>,
    pub audit_uid: Option<u32>,
    pub audit_name: Option<String>,
}

impl WhodataInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, uid: u32, name: impl Into<String>) -> Self {
        self.user_id = Some(uid);
        self.user_name = Some(name.into());
        self
    }

    pub fn with_process(mut self, pid: u32, ppid: Option<u32>, name: impl Into<String>) -> Self {
        self.process_id = Some(pid);
        self.parent_process_id = ppid;
        self.process_name = Some(name.into());
        self
    }
}
