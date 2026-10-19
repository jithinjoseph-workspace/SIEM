//! `monitord/monitor_actions.c` plus the authd client it uses
//! (`get_agent_id_from_name`, `auth_connect`, `auth_remove_agent`).

use siem_cjson::Json;
use siem_ipc::mq::queues::{LOCALFILE_MQ, SECURE_MQ};

use crate::monitord::Monitor;
use crate::{mq, ARGV0, AUTH_LOCAL_SOCK, KEYS_FILE, LOGFILE, LOGJSONFILE, QUEUE_SEND};

/// `snprintf(str, OS_SIZE_1024, ...)`
fn cut1024(s: String) -> Vec<u8> {
    let mut b = s.into_bytes();
    b.truncate(1023);
    b
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// String member of an agent info row (`cJSON_IsString`).
fn s<'a>(j: &'a Json, k: &str) -> Option<std::borrow::Cow<'a, str>> {
    j.get(k).filter(|v| v.is_string()).and_then(|v| v.as_str())
}

impl Monitor {
    /// `monitor_send_deletion_msg`
    pub fn send_deletion_msg(&mut self, agent: &str) {
        let msg = cut1024(format!("ossec: Agent removed: '{agent}'."));
        if mq::send(&self.queue, &msg, ARGV0, LOCALFILE_MQ) < 0 {
            self.queue = None;
            self.log.debug1(format!("Could not generate removed agent alert for '{agent}'"));
            self.log.debug1(QUEUE_SEND);
        }
    }

    /// `monitor_send_disconnection_msg`
    pub fn send_disconnection_msg(&mut self, agent: &str) {
        let msg = cut1024(format!("1:{ARGV0}:ossec: Agent disconnected: '{agent}'."));
        match self.send_agent_msg(agent, &msg) {
            0 => {}
            2 => self.send_deletion_msg(agent),
            _ => self.log.debug1(format!("Could not generate disconnected agent alert for '{agent}'")),
        }
    }

    /// `mon_send_agent_msg`: 0 sent, 2 agent not in the database, 1 error.
    fn send_agent_msg(&mut self, agent: &str, msg: &[u8]) -> i32 {
        let Some(dash) = agent.rfind('-') else { return 1 };
        let ag_ip = &agent[dash + 1..];
        let name_size = agent.len() - ag_ip.len();
        if name_size > 128 {
            return 1;
        }
        let ag_name = &agent[..name_size - 1];
        let ag_id = self.wdb.find_agent(&self.log, ag_name, ag_ip);
        if ag_id > 0 {
            let header = format!("[{ag_id:03}] ({ag_name}) {ag_ip}");
            if mq::send(&self.queue, msg, &header, SECURE_MQ) < 0 {
                self.queue = None;
                self.log.debug1(QUEUE_SEND);
                return 1;
            }
            0
        } else if ag_id == -2 {
            2
        } else {
            1
        }
    }

    /// `monitor_agents_disconnection`
    pub fn agents_disconnection(&mut self) {
        // The master disconnects and alerts the agents of its own DB: no synchronization needed.
        let ids = self.wdb.disconnect_agents(&self.log, now() - self.mond.global.agents_disconnection_time, "synced");
        if self.mond.monitor_agents != 0 {
            for id in ids {
                let key = id.to_string();
                if !self.to_alert.iter().any(|(k, _)| *k == key) {
                    self.to_alert.push((key, now()));
                }
            }
        }
    }

    /// `"<name>-<register_ip>"` of a `get-agent-info` row with every field set.
    fn name_ip(row: &Json, need_status: bool) -> Option<(String, String, i32)> {
        let status = s(row, "connection_status");
        let ka = row.get("last_keepalive").filter(|v| v.is_number())?.as_i32()?;
        let (name, ip) = (s(row, "name")?, s(row, "register_ip")?);
        if need_status && status.is_none() {
            return None;
        }
        Some((format!("{name}-{ip}"), status.map(|c| c.into_owned()).unwrap_or_default(), ka))
    }

    /// `monitor_agents_alert`
    pub fn agents_alert(&mut self) {
        let keys: Vec<String> = self.to_alert.iter().map(|(k, _)| k.clone()).collect();
        for key in keys {
            let id = key.parse::<i32>().unwrap_or(0);
            match self.wdb.get_agent_info(&self.log, id) {
                Some(info) => {
                    let Some(row) = info.children().first().copied() else { continue };
                    let Some((agent, status, ka)) = Self::name_ip(row, true) else { continue };
                    if status == "active" {
                        // The agent is connected again
                        self.to_alert.retain(|(k, _)| *k != key);
                    } else if (ka as i64) < now() - (self.mond.global.agents_disconnection_time + self.mond.global.agents_disconnection_alert_time) {
                        self.send_disconnection_msg(&agent);
                        self.to_alert.retain(|(k, _)| *k != key);
                    }
                }
                None => {
                    self.log.debug1(format!("Unable to retrieve agent's '{key}' data from Wazuh DB"));
                    self.to_alert.retain(|(k, _)| *k != key);
                }
            }
        }
    }

    /// `monitor_agents_deletion`
    pub fn agents_deletion(&mut self) {
        for id in self.wdb.agents_by_connection_status(&self.log, "disconnected") {
            match self.wdb.get_agent_info(&self.log, id) {
                Some(info) => {
                    let Some(row) = info.children().first().copied() else { continue };
                    let Some((agent, _, ka)) = Self::name_ip(row, false) else { continue };
                    let limit = self.mond.global.agents_disconnection_time + self.mond.delete_old_agents as i64 * 60;
                    if (ka as i64) < now() - limit && self.delete_old_agent(&agent) == 0 {
                        self.send_deletion_msg(&agent);
                    }
                }
                None => {
                    self.log.debug1(format!("Unable to retrieve agent's '{id}' data from Wazuh DB"));
                    let key = id.to_string();
                    self.to_alert.retain(|(k, _)| *k != key);
                }
            }
        }
    }

    /// `monitor_logs`
    pub fn monitor_logs(&self, check_logs_size: bool) {
        let m = &self.mond;
        if !check_logs_size && m.rotate_log != 0 {
            std::thread::sleep(std::time::Duration::from_secs(m.day_wait.max(0) as u64));
            // Daily rotation and compression of ossec.log/ossec.json
            crate::rotate_log::w_rotate_log(&self.log, m.compress != 0, m.keep_log_days, true, false, m.daily_rotations);
        } else if check_logs_size && m.rotate_log != 0 && m.size_rotate > 0 {
            if std::fs::metadata(LOGFILE).is_ok_and(|md| md.len() >= m.size_rotate) {
                crate::rotate_log::w_rotate_log(&self.log, m.compress != 0, m.keep_log_days, false, false, m.daily_rotations);
            }
            if std::fs::metadata(LOGJSONFILE).is_ok_and(|md| md.len() >= m.size_rotate) {
                crate::rotate_log::w_rotate_log(&self.log, m.compress != 0, m.keep_log_days, false, true, m.daily_rotations);
            }
        }
    }

    /// `delete_old_agent`: 0 when authd removed the agent.
    pub fn delete_old_agent(&self, agent: &str) -> i32 {
        let end = agent.rfind('-').unwrap_or(0);
        let agent_name = &agent[..end.min(127)];
        let Some(id) = get_agent_id_from_name(&self.log, agent_name) else { return -1 };
        let rt = self.rt.clone();
        let Ok(mut sock) = rt.block_on(siem_ipc::local::LocalStream::connect(AUTH_LOCAL_SOCK)) else {
            self.log.debug1("Monitord could not connect to to Authd socket. Is Authd running?");
            return -1;
        };
        self.auth_remove_agent(&mut sock, &id)
    }

    /// `auth_remove_agent(sock, id, json_format = 1)`
    fn auth_remove_agent(&self, sock: &mut siem_ipc::local::LocalStream, id: &str) -> i32 {
        let mut args = Json::object();
        args.add("id", Json::string(id));
        let mut req = Json::object();
        req.add("arguments", args);
        req.add("function", Json::string("remove"));
        let out = req.to_string_unformatted();
        let rt = self.rt.clone();
        if let Err(e) = rt.block_on(siem_ipc::framing::send(sock, out.as_bytes())) {
            crate::fatal(&self.log, &format!("OS_SendSecureTCP(): {e}"));
        }
        let buf = match rt.block_on(siem_ipc::framing::recv(sock, siem_ipc::OS_MAXSTR)) {
            Ok(b) if b.is_empty() => crate::fatal(&self.log, "Empty message from local server."),
            Ok(b) => b,
            Err(siem_ipc::framing::FrameError::Closed) => crate::fatal(&self.log, "Empty message from local server."),
            Err(e) => crate::fatal(&self.log, &format!("OS_RecvSecureTCP(): {e}")),
        };
        let Some(resp) = siem_cjson::parse(&buf) else { crate::fatal(&self.log, "Parsing JSON response.") };
        let Some(err) = resp.get("error") else { crate::fatal(&self.log, "No such status from response.") };
        if err.as_i32().unwrap_or(0) > 0 {
            // json_format: the raw response goes to stdout
            print!("{}", String::from_utf8_lossy(&buf));
            return -1;
        }
        match self.wdb.query_once(&self.log, &format!("wazuhdb remove {id}")) {
            0 => 0,
            e => {
                self.log.error(format!("Could not remove the agent {id}. Error: {e}."));
                -1
            }
        }
    }
}

/// `get_agent_id_from_name` (reads `etc/client.keys`).
pub fn get_agent_id_from_name(log: &siem_log::WLog, agent_name: &str) -> Option<String> {
    let Ok(data) = std::fs::read(KEYS_FILE) else {
        log.debug1(format!("Couldnt open file '{KEYS_FILE}'"));
        return None;
    };
    for line in data.split_inclusive(|&c| c == b'\n') {
        let Some(parts) = siem_regex::strings::str_break_bytes(b' ', line, 4) else { continue };
        if parts.len() < 3 {
            return None;
        }
        if parts[1] == agent_name.as_bytes() {
            return Some(String::from_utf8_lossy(&parts[0]).into_owned());
        }
    }
    None
}
