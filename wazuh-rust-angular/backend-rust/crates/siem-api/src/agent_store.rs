//! The in-memory state of agents that report through the older siem-agent path (the
//! ProVigil agents' state is in provigil-db): inventory, FIM entries and SCA results per agent,
//! for the host pages and the FIM / SCA event handling. Moved here from the old database crate.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


// ---- models

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FimEntryType {
    File,
    RegistryKey,
    RegistryValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimEntry {
    pub full_path: String,
    pub file_name: String,
    pub entry_type: FimEntryType,
    pub size: Option<u64>,
    pub perm: Option<String>,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub mtime: u64,
    pub inode: Option<u64>,
    pub changes: u32,
    pub date: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FimAction {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimDelta {
    pub path: String,
    pub action: FimAction,
    pub old_entry: Option<FimEntry>,
    pub new_entry: Option<FimEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysProgram {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub vendor: Option<String>,
    pub format: Option<String>, // deb, rpm, win, pkg
    pub description: Option<String>,
    pub size_bytes: Option<u64>,
    pub install_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SysHwInfo {
    pub board_serial: Option<String>,
    pub cpu_name: String,
    pub cpu_cores: usize,
    pub cpu_mhz: f32,
    pub ram_total_mb: u64,
    pub ram_free_mb: u64,
    pub ram_usage_percent: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysOsInfo {
    pub hostname: String,
    pub architecture: String,
    pub os_name: String,
    pub os_version: String,
    pub os_codename: Option<String>,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_build: Option<String>,
    pub platform: String,
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysPort {
    pub protocol: String, // tcp, udp
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String, // LISTEN, ESTABLISHED
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysNetIface {
    pub name: String,
    pub adapter: Option<String>,
    pub iface_type: Option<String>,
    pub state: String,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScaStatus {
    Passed,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaCheckResult {
    pub policy_id: String,
    pub check_id: u32,
    pub title: String,
    pub description: String,
    pub rationale: Option<String>,
    pub remediation: Option<String>,
    pub status: ScaStatus,
}

// ---- fim store

#[derive(Debug, Clone, Default)]
pub struct FimStore {
    entries: HashMap<String, FimEntry>,
}

impl FimStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Upsert a FIM entry, automatically detecting whether it was Added or Modified
    pub fn upsert(&mut self, mut new_entry: FimEntry) -> Option<FimDelta> {
        let path = new_entry.full_path.clone();

        if let Some(old) = self.entries.get_mut(&path) {
            // Check if checksum, size, or perm changed
            let checksum_changed = old.sha256 != new_entry.sha256
                || old.md5 != new_entry.md5
                || old.sha1 != new_entry.sha1;
            let size_changed = old.size != new_entry.size;
            let perm_changed = old.perm != new_entry.perm;
            let mtime_changed = old.mtime != new_entry.mtime;

            if checksum_changed || size_changed || perm_changed || mtime_changed {
                new_entry.changes = old.changes + 1;
                let delta = FimDelta {
                    path: path.clone(),
                    action: FimAction::Modified,
                    old_entry: Some(old.clone()),
                    new_entry: Some(new_entry.clone()),
                };
                *old = new_entry;
                Some(delta)
            } else {
                // Unchanged
                None
            }
        } else {
            // New file added
            new_entry.changes = 1;
            let delta = FimDelta {
                path: path.clone(),
                action: FimAction::Added,
                old_entry: None,
                new_entry: Some(new_entry.clone()),
            };
            self.entries.insert(path, new_entry);
            Some(delta)
        }
    }

    /// Delete a FIM entry (e.g. file removed on agent)
    pub fn delete(&mut self, path: &str) -> Option<FimDelta> {
        if let Some(old) = self.entries.remove(path) {
            Some(FimDelta {
                path: path.to_string(),
                action: FimAction::Deleted,
                old_entry: Some(old),
                new_entry: None,
            })
        } else {
            None
        }
    }

    pub fn get(&self, path: &str) -> Option<&FimEntry> {
        self.entries.get(path)
    }

    pub fn list(&self) -> Vec<FimEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod fim_tests {
    use super::*;

    #[test]
    fn test_fim_upsert_added_and_modified() {
        let mut store = FimStore::new();

        let file1 = FimEntry {
            full_path: "/etc/passwd".to_string(),
            file_name: "passwd".to_string(),
            entry_type: FimEntryType::File,
            size: Some(1024),
            perm: Some("0644".to_string()),
            uid: Some("0".to_string()),
            gid: Some("0".to_string()),
            md5: Some("md5_initial".to_string()),
            sha1: None,
            sha256: Some("sha256_initial".to_string()),
            mtime: 1700000000,
            inode: Some(12345),
            changes: 0,
            date: 1700000000,
        };

        // 1. Initial addition
        let delta1 = store.upsert(file1.clone()).expect("Should generate Added delta");
        assert_eq!(delta1.action, FimAction::Added);
        assert_eq!(store.get("/etc/passwd").unwrap().changes, 1);

        // 2. Exact same file: no delta
        let delta_noop = store.upsert(file1.clone());
        assert!(delta_noop.is_none());

        // 3. File modified: changed sha256
        let mut modified = file1;
        modified.sha256 = Some("sha256_modified".to_string());
        modified.size = Some(1080);
        let delta2 = store.upsert(modified).expect("Should generate Modified delta");
        assert_eq!(delta2.action, FimAction::Modified);
        assert_eq!(store.get("/etc/passwd").unwrap().changes, 2);

        // 4. File deleted
        let delta3 = store.delete("/etc/passwd").expect("Should generate Deleted delta");
        assert_eq!(delta3.action, FimAction::Deleted);
        assert_eq!(store.total_entries(), 0);
    }
}

// ---- syscollector store

#[derive(Debug, Clone, Default)]
pub struct SyscollectorStore {
    pub hw_info: Option<SysHwInfo>,
    pub os_info: Option<SysOsInfo>,
    pub ports: Vec<SysPort>,
    pub programs: HashMap<String, SysProgram>,
    pub netifaces: Vec<SysNetIface>,
}

impl SyscollectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_hw_info(&mut self, info: SysHwInfo) {
        self.hw_info = Some(info);
    }

    pub fn set_os_info(&mut self, info: SysOsInfo) {
        self.os_info = Some(info);
    }

    pub fn set_ports(&mut self, ports: Vec<SysPort>) {
        self.ports = ports;
    }

    pub fn set_netifaces(&mut self, ifaces: Vec<SysNetIface>) {
        self.netifaces = ifaces;
    }

    /// Synchronize full software inventory, returning (newly_installed, uninstalled)
    pub fn sync_programs(
        &mut self,
        new_programs: Vec<SysProgram>,
    ) -> (Vec<SysProgram>, Vec<SysProgram>) {
        let mut new_map = HashMap::new();
        for prog in new_programs {
            new_map.insert(prog.name.clone(), prog);
        }

        let mut installed = Vec::new();
        let mut uninstalled = Vec::new();

        // Check for new installations
        for (name, prog) in &new_map {
            if !self.programs.contains_key(name) {
                installed.push(prog.clone());
            }
        }

        // Check for uninstalled packages
        for (name, prog) in &self.programs {
            if !new_map.contains_key(name) {
                uninstalled.push(prog.clone());
            }
        }

        self.programs = new_map;
        (installed, uninstalled)
    }

    pub fn get_program(&self, name: &str) -> Option<&SysProgram> {
        self.programs.get(name)
    }

    pub fn total_programs(&self) -> usize {
        self.programs.len()
    }

    pub fn listening_ports(&self) -> Vec<&SysPort> {
        self.ports
            .iter()
            .filter(|p| p.state.eq_ignore_ascii_case("listen") || p.state.eq_ignore_ascii_case("listening"))
            .collect()
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    #[test]
    fn test_sync_programs_delta() {
        let mut store = SyscollectorStore::new();

        let initial = vec![
            SysProgram {
                name: "openssh-server".to_string(),
                version: "8.9p1".to_string(),
                architecture: Some("amd64".to_string()),
                vendor: Some("Ubuntu".to_string()),
                format: Some("deb".to_string()),
                description: None,
                size_bytes: Some(1500000),
                install_time: None,
            },
            SysProgram {
                name: "curl".to_string(),
                version: "7.81.0".to_string(),
                architecture: Some("amd64".to_string()),
                vendor: Some("Ubuntu".to_string()),
                format: Some("deb".to_string()),
                description: None,
                size_bytes: Some(400000),
                install_time: None,
            },
        ];

        let (installed1, uninstalled1) = store.sync_programs(initial);
        assert_eq!(installed1.len(), 2);
        assert_eq!(uninstalled1.len(), 0);
        assert_eq!(store.total_programs(), 2);

        // Next scan: curl removed, nginx installed
        let second_scan = vec![
            SysProgram {
                name: "openssh-server".to_string(),
                version: "8.9p1".to_string(),
                architecture: Some("amd64".to_string()),
                vendor: Some("Ubuntu".to_string()),
                format: Some("deb".to_string()),
                description: None,
                size_bytes: Some(1500000),
                install_time: None,
            },
            SysProgram {
                name: "nginx".to_string(),
                version: "1.24.0".to_string(),
                architecture: Some("amd64".to_string()),
                vendor: Some("Ubuntu".to_string()),
                format: Some("deb".to_string()),
                description: None,
                size_bytes: Some(1200000),
                install_time: None,
            },
        ];

        let (installed2, uninstalled2) = store.sync_programs(second_scan);
        assert_eq!(installed2.len(), 1);
        assert_eq!(installed2[0].name, "nginx");
        assert_eq!(uninstalled2.len(), 1);
        assert_eq!(uninstalled2[0].name, "curl");
        assert_eq!(store.total_programs(), 2);
    }
}

// ---- sca store

#[derive(Debug, Clone, Default)]
pub struct ScaPolicyStore {
    pub policy_id: String,
    pub checks: HashMap<u32, ScaCheckResult>,
}

impl ScaPolicyStore {
    pub fn new(policy_id: String) -> Self {
        Self {
            policy_id,
            checks: HashMap::new(),
        }
    }

    pub fn upsert_check(&mut self, check: ScaCheckResult) {
        self.checks.insert(check.check_id, check);
    }

    pub fn passed_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::Passed)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::Failed)
            .count()
    }

    pub fn not_applicable_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::NotApplicable)
            .count()
    }

    pub fn compliance_score(&self) -> f32 {
        let passed = self.passed_count() as f32;
        let failed = self.failed_count() as f32;
        let total_applicable = passed + failed;

        if total_applicable == 0.0 {
            100.0
        } else {
            (passed / total_applicable) * 100.0
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScaStore {
    policies: HashMap<String, ScaPolicyStore>,
}

impl ScaStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_policy_mut(&mut self, policy_id: &str) -> &mut ScaPolicyStore {
        self.policies
            .entry(policy_id.to_string())
            .or_insert_with(|| ScaPolicyStore::new(policy_id.to_string()))
    }

    pub fn get_policy(&self, policy_id: &str) -> Option<&ScaPolicyStore> {
        self.policies.get(policy_id)
    }

    pub fn total_policies(&self) -> usize {
        self.policies.len()
    }

    pub fn list_policies(&self) -> Vec<&ScaPolicyStore> {
        self.policies.values().collect()
    }
}

#[cfg(test)]
mod sca_tests {
    use super::*;

    #[test]
    fn test_sca_compliance_score() {
        let mut store = ScaStore::new();
        let policy = store.get_policy_mut("cis_ubuntu24-04");

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1001,
            title: "Ensure /tmp is configured with nodev".to_string(),
            description: "Check fstab for /tmp mount options".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Passed,
        });

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1002,
            title: "Ensure root login via SSH is disabled".to_string(),
            description: "Check sshd_config PermitRootLogin no".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Failed,
        });

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1003,
            title: "Ensure legacy rsh-server is not installed".to_string(),
            description: "Check rsh-server package absence".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Passed,
        });

        // 2 passed, 1 failed => 2 / 3 * 100 = 66.666%
        let score = policy.compliance_score();
        assert!((score - 66.666).abs() < 0.1);
        assert_eq!(policy.passed_count(), 2);
        assert_eq!(policy.failed_count(), 1);
    }
}

// ---- per agent

pub struct AgentDatabase {
    pub agent_id: String,
    pub agent_name: String,
    pub fim: FimStore,
    pub syscollector: SyscollectorStore,
    pub sca: ScaStore,
    pub last_sync: DateTime<Utc>,
}

impl AgentDatabase {
    pub fn new(agent_id: &str, agent_name: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            agent_name: agent_name.to_string(),
            fim: FimStore::new(),
            syscollector: SyscollectorStore::new(),
            sca: ScaStore::new(),
            last_sync: Utc::now(),
        }
    }

    pub fn mark_synced(&mut self) {
        self.last_sync = Utc::now();
    }
}

// ---- all agents

#[derive(Clone)]
pub struct AgentStore {
    agents: Arc<RwLock<HashMap<String, Arc<RwLock<AgentDatabase>>>>>,
}

impl Default for AgentStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentStore {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_or_create(&self, agent_id: &str, agent_name: &str) -> Arc<RwLock<AgentDatabase>> {
        let mut guard = self.agents.write().unwrap();
        guard
            .entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(AgentDatabase::new(agent_id, agent_name))))
            .clone()
    }

    pub fn get(&self, agent_id: &str) -> Option<Arc<RwLock<AgentDatabase>>> {
        let guard = self.agents.read().unwrap();
        guard.get(agent_id).cloned()
    }

    pub fn list_agent_ids(&self) -> Vec<String> {
        let guard = self.agents.read().unwrap();
        guard.keys().cloned().collect()
    }

    pub fn total_agents(&self) -> usize {
        let guard = self.agents.read().unwrap();
        guard.len()
    }
}
