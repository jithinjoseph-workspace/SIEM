//! Running one response, undoing responses whose time is up, and undoing all at shutdown.

use provigil_json::Json;

use crate::process::{Bind, Line, Program};
use crate::*;

/// Replaces the value of the first member `key` (any case) of an object, under the key `key`;
/// nothing when there is no such member.
fn replace(obj: Option<&mut Json>, key: &str, v: Json) {
    if let Some(Json::Object(m)) = obj {
        if let Some(e) = m.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes())) {
            *e = (key.as_bytes().to_vec(), v);
        }
    }
}

/// A program's answer: an object with a number `version`, an object `origin`, a text `command`
/// and an object `parameters`.
fn answer(line: &[u8]) -> Option<Json> {
    let (j, _) = provigil_json::parse_with_opts(line, false).ok()?;
    let ok = matches!(j.get("version"), Some(Json::Number { .. }))
        && matches!(j.get("origin"), Some(Json::Object(_)))
        && matches!(j.get("command"), Some(Json::String(_)))
        && matches!(j.get("parameters"), Some(Json::Object(_)));
    ok.then_some(j)
}

/// `-key1-key2...` from the answer's `parameters.keys` (texts only), at most 4,095 bytes.
fn keys(j: &Json) -> Option<String> {
    let keys = match j.get("parameters")?.get("keys")? {
        k @ Json::Array(_) => k,
        _ => return None,
    };
    let mut out = String::new();
    for k in keys.children() {
        if let Some(s) = k.as_str() {
            if out.len() + s.len() + 2 > KEY_ROOM {
                break;
            }
            out.push('-');
            out.push_str(&s);
        }
    }
    (!out.is_empty()).then_some(out)
}

impl Execd {
    fn launch_failed(&self, e: &std::io::Error) {
        self.log.error(format!("(1317): Could not launch command {} ({})", strerror(e), errno(e)));
    }

    /// How long a response program may take to answer, and again to end.
    fn limit(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.request_timeout.load(std::sync::atomic::Ordering::SeqCst).max(1) as u64)
    }

    /// Waits for a program to end, stopping it after the limit.
    fn finish(&self, p: Program, program: &str) {
        if p.close_within(Some(self.limit())).1 {
            self.log.warn(format!("Active response program '{program}' did not end within {} seconds: stopped.", self.limit().as_secs()));
        }
    }

    /// Runs `program` with `message` on its input and waits (undoing a response).
    fn undo(&self, program: &str, message: &[u8]) {
        match Program::start(&self.home, program, &[program], Bind { stdin: true, ..Default::default() }) {
            Ok(mut p) => {
                p.write_line(message);
                self.finish(p, program);
            }
            Err(e) => self.launch_failed(&e),
        }
    }

    /// Undoes everything pending (at shutdown).
    pub fn shutdown(&self) {
        self.log.info(SHUTDOWN);
        let all = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        for p in all {
            self.log.debug2(format!("Delete pending AR: '{}' '{}'", p.program, String::from_utf8_lossy(&p.message)));
            self.undo(&p.program, &p.message);
        }
    }

    /// Undoes the responses whose time is up; how many.
    pub fn expire(&self) -> usize {
        let t = now();
        let mut list = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut done = 0;
        let mut i = 0;
        while i < list.len() {
            if t - list[i].added > list[i].seconds as i64 {
                let p = list.remove(i);
                self.log.debug(format!("Executing command '{} {}' after a timeout of '{}s'", p.program, String::from_utf8_lossy(&p.message), p.seconds));
                self.undo(&p.program, &p.message);
                done += 1;
            } else {
                i += 1;
            }
        }
        done
    }

    /// Runs the response a message asks for; whether a program ran to the end of the protocol.
    pub fn run(&self, msg: &[u8]) -> bool {
        let t = now();
        let shown = || String::from_utf8_lossy(msg).into_owned();
        let Some(mut root) = provigil_json::parse(msg) else {
            self.log.error(format!("(1315): Invalid JSON message: '{}'", shown()));
            return false;
        };
        let name = match root.get("command") {
            Some(Json::String(_)) => root.get("command").and_then(Json::as_str).unwrap_or_default().into_owned(),
            _ => {
                self.log.error(format!("(1316): Invalid AR command: '{}'", shown()));
                return false;
            }
        };
        #[cfg(unix)]
        if name == "restart-wazuh" {
            self.run_detached(&["active-response/bin/restart.sh", "agent"]);
            return false;
        }
        let found = self.command(&name).or_else(|| {
            self.read_table();
            self.command(&name)
        });
        let Some((program, mut seconds)) = found else {
            self.log.error(format!("(1311): Invalid command name '{name}' provided."));
            return false;
        };
        if program.is_empty() {
            return false;
        }

        replace(Some(&mut root), "command", Json::string("add"));
        replace(root.get_mut("origin"), "module", Json::string(NAME));
        if let Some(p) = root.get_mut("parameters") {
            p.add("program", Json::string(&program));
        }
        let add = root.print_unformatted();
        self.log.debug(format!("Executing command '{program} {}'", String::from_utf8_lossy(&add)));
        let mut p = match Program::start(&self.home, &program, &[&program], Bind { stdin: true, stdout: true, stderr: false }) {
            Ok(p) => p,
            Err(e) => {
                self.launch_failed(&e);
                return false;
            }
        };
        p.write_line(&add);
        let reply = match p.read_line_within(8192, Some(self.limit())) {
            Line::Text(r) => r,
            Line::End => {
                self.log.debug(format!("Active response won't be added to timeout list. Message not received with alert keys from script '{program}'"));
                self.finish(p, &program);
                return false;
            }
            Line::TimedOut => {
                self.log.warn(format!("Active response program '{program}' did not answer within {} seconds: stopped.", self.limit().as_secs()));
                p.close_within(Some(std::time::Duration::ZERO));
                return false;
            }
        };

        // one entry per program and keys
        let mut key = cut(basename(&program), KEY_ROOM - 1);
        if let Some(a) = answer(&reply) {
            if a.get("command").and_then(Json::as_str).as_deref() == Some("check_keys") {
                if let Some(k) = keys(&a) {
                    if key.len() + k.len() >= KEY_ROOM {
                        self.log.warn(format!("Active response key exceeds maximum size ({KEY_ROOM}). Truncating keys."));
                    }
                    let room = KEY_ROOM - key.len() - 1;
                    key.push_str(&cut(&k, room + 1));
                }
            }
        }

        let mut again = false;
        if seconds != 0 {
            let offenders = self.offender_minutes();
            if let Some(counts) = self.repeats.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                match counts.get(&key).copied() {
                    Some(times) => {
                        let n = offenders.len() as i32;
                        let longer = if times >= n {
                            offenders[(n - 1).max(0) as usize] * 60
                        } else {
                            counts.insert(key.clone(), times + 1);
                            offenders[times.max(0) as usize] * 60
                        };
                        self.log.debug(format!("Repeated offender. Setting timeout to '{longer}s'"));
                        seconds = longer;
                    }
                    None => {
                        counts.insert(key.clone(), 0);
                    }
                }
            }
            let mut list = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(e) = list.iter_mut().find(|e| e.key == key) {
                again = true;
                self.log.debug("Command already received, updating time of addition to now.");
                e.added = t;
                e.seconds = seconds;
            } else {
                replace(Some(&mut root), "command", Json::string("delete"));
                let e = Pending { program: program.clone(), message: root.print_unformatted(), key, added: t, seconds };
                self.log.debug(format!("Adding command '{} {}' to the timeout list, with a timeout of '{}s'.", e.program, String::from_utf8_lossy(&e.message), e.seconds));
                list.push(e);
            }
        }

        // go on, or stop: the response is already in place
        replace(Some(&mut root), "command", Json::string(if again { "abort" } else { "continue" }));
        p.write_line(&root.print_unformatted());
        self.finish(p, &program);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_and_keys() {
        let j = answer(br#"{"version":1,"origin":{},"command":"check_keys","parameters":{"keys":["1.2.3.4",5,"x"]}}"#).unwrap();
        assert_eq!(keys(&j).as_deref(), Some("-1.2.3.4-x"));
        assert!(answer(br#"{"version":"1","origin":{},"command":"x","parameters":{}}"#).is_none());
        let mut o = provigil_json::parse(br#"{"Command":"x","origin":{"name":"n"}}"#).unwrap();
        replace(Some(&mut o), "command", Json::string("add"));
        replace(o.get_mut("origin"), "module", Json::string("m"));
        assert_eq!(o.print_unformatted(), br#"{"command":"add","origin":{"name":"n"}}"#);
    }
}
