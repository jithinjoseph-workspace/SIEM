use crate::global_db::ConnectionStatus;
use crate::manager_db::WazuhDbManager;
use crate::models::{FimEntry, FimEntryType, ScaCheckResult, ScaStatus};
use serde_json::json;
use std::sync::Arc;

pub struct WdbWireProtocol {
    manager: Arc<WazuhDbManager>,
}

impl WdbWireProtocol {
    pub fn new(manager: Arc<WazuhDbManager>) -> Self {
        Self { manager }
    }

    /// Evaluates a raw Wazuh DB text socket command string and returns response
    pub fn execute_command(&self, raw_cmd: &str) -> String {
        let trimmed = raw_cmd.trim();
        let mut parts = trimmed.split_whitespace();
        let target = match parts.next() {
            Some(t) => t,
            None => return "err Empty command".to_string(),
        };

        if target == "global" {
            self.handle_global_command(parts.collect())
        } else if target == "agent" {
            let agent_id = match parts.next() {
                Some(id) => id,
                None => return "err Missing agent id".to_string(),
            };
            self.handle_agent_command(agent_id, parts.collect())
        } else {
            "err Unknown target (must be 'global' or 'agent')".to_string()
        }
    }

    fn handle_global_command(&self, args: Vec<&str>) -> String {
        if args.is_empty() {
            return "err Missing global command".to_string();
        }

        match args[0] {
            "insert-agent" => {
                // insert-agent <id> <name> [ip] [key] [group]
                if args.len() < 3 {
                    return "err Usage: global insert-agent <id> <name> [ip] [key] [group]".to_string();
                }
                let id: u32 = match args[1].parse() {
                    Ok(i) => i,
                    Err(_) => return "err Invalid agent id".to_string(),
                };
                let name = args[2];
                let ip = args.get(3).copied();
                let key = args.get(4).copied();
                let group = args.get(5).copied();

                match self.manager.global.insert_agent(id, name, ip, ip, key, group) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("err {e}"),
                }
            }
            "update-keepalive" => {
                // update-keepalive <id> <status>
                if args.len() < 3 {
                    return "err Usage: global update-keepalive <id> <status>".to_string();
                }
                let id: u32 = match args[1].parse() {
                    Ok(i) => i,
                    Err(_) => return "err Invalid agent id".to_string(),
                };
                let status = ConnectionStatus::from_str_loose(args[2]);
                if self.manager.global.update_agent_keepalive(id, status) {
                    "ok".to_string()
                } else {
                    "err Agent not found".to_string()
                }
            }
            "get-agent-info" => {
                // get-agent-info <id>
                if args.len() < 2 {
                    return "err Usage: global get-agent-info <id>".to_string();
                }
                let id: u32 = match args[1].parse() {
                    Ok(i) => i,
                    Err(_) => return "err Invalid agent id".to_string(),
                };
                if let Some(agent) = self.manager.global.get_agent_info(id) {
                    let j = json!(agent);
                    format!("ok {}", j)
                } else {
                    "err Agent not found".to_string()
                }
            }
            "get-all-agents" => {
                let agents = self.manager.global.get_all_agents();
                let j = json!(agents);
                format!("ok {}", j)
            }
            "disconnect-agents" => {
                // disconnect-agents <timeout_sec>
                let timeout: i64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1800);
                let count = self.manager.global.disconnect_stale_agents(timeout);
                format!("ok Disconnected {count} agents")
            }
            _ => format!("err Unknown global action '{}'", args[0]),
        }
    }

    fn handle_agent_command(&self, agent_id: &str, args: Vec<&str>) -> String {
        if args.is_empty() {
            return "err Missing agent command".to_string();
        }

        let agent_db = self.manager.get_or_create(agent_id, "unknown");

        match args[0] {
            "fim" => {
                // fim save <path> <size> <perm> <uid> <gid> <md5> <sha256> <mtime> <inode>
                if args.len() >= 3 && args[1] == "save" {
                    let path = args[2];
                    let size = args.get(3).and_then(|s| s.parse().ok());
                    let perm = args.get(4).map(|s| s.to_string());
                    let uid = args.get(5).map(|s| s.to_string());
                    let gid = args.get(6).map(|s| s.to_string());
                    let md5 = args.get(7).map(|s| s.to_string());
                    let sha256 = args.get(8).map(|s| s.to_string());
                    let mtime: u64 = args.get(9).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let inode = args.get(10).and_then(|s| s.parse().ok());

                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(path)
                        .to_string();

                    let entry = FimEntry {
                        full_path: path.to_string(),
                        file_name,
                        entry_type: FimEntryType::File,
                        size,
                        perm,
                        uid,
                        gid,
                        md5,
                        sha1: None,
                        sha256,
                        mtime,
                        inode,
                        changes: 0,
                        date: mtime,
                    };

                    let mut db = agent_db.write().unwrap();
                    let delta = db.fim.upsert(entry);
                    db.mark_synced();

                    if let Some(d) = delta {
                        format!("ok Action: {:?}", d.action)
                    } else {
                        "ok Unchanged".to_string()
                    }
                } else if args.len() >= 3 && args[1] == "get" {
                    let path = args[2];
                    let db = agent_db.read().unwrap();
                    if let Some(entry) = db.fim.get(path) {
                        let j = json!(entry);
                        format!("ok {}", j)
                    } else {
                        "err File not found".to_string()
                    }
                } else {
                    "err Invalid fim command".to_string()
                }
            }
            "rootcheck" => {
                // rootcheck save <log> <date> [pci_dss] [cis]
                if args.len() >= 3 && args[1] == "save" {
                    let log = args[2];
                    let date: i64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let pci = args.get(4).map(|s| s.to_string());
                    let cis = args.get(5).map(|s| s.to_string());

                    let db = agent_db.read().unwrap();
                    db.rootcheck.save_event(log, date, pci, cis);
                    "ok".to_string()
                } else {
                    "err Invalid rootcheck command".to_string()
                }
            }
            "sca" => {
                // sca save <policy_id> <check_id> <title> <result>
                if args.len() >= 5 && args[1] == "save" {
                    let policy_id = args[2];
                    let check_id: u32 = match args[3].parse() {
                        Ok(c) => c,
                        Err(_) => return "err Invalid check_id".to_string(),
                    };
                    let title = args[4];
                    let result_str = args.get(5).unwrap_or(&"passed");
                    let status = match *result_str {
                        "failed" => ScaStatus::Failed,
                        _ => ScaStatus::Passed,
                    };

                    let check = ScaCheckResult {
                        policy_id: policy_id.to_string(),
                        check_id,
                        title: title.to_string(),
                        description: "".to_string(),
                        rationale: None,
                        remediation: None,
                        status,
                    };

                    let mut db = agent_db.write().unwrap();
                    let policy = db.sca.get_policy_mut(policy_id);
                    policy.upsert_check(check);
                    "ok".to_string()
                } else {
                    "err Invalid sca command".to_string()
                }
            }
            _ => format!("err Unknown agent action '{}'", args[0]),
        }
    }
}
