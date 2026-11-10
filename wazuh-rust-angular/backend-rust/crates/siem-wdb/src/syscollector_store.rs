use std::collections::HashMap;
use crate::models::{SysHwInfo, SysNetIface, SysOsInfo, SysPort, SysProgram};

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
mod tests {
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
