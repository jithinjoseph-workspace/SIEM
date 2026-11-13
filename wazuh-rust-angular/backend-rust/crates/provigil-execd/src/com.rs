//! Requests on `queue/sockets/com`: `unmerge`, `uncompress`, `restart`, `reload`,
//! `lock_restart`, `getconfig` and `check-manager-configuration`.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;

use provigil_json::Json;

use crate::process::{capture, Captured};
use crate::*;

/// The manager programs `check-manager-configuration` runs with `-t`, in this order.
pub const PROGRAMS: [&str; 5] = ["bin/provigil-db", "bin/provigil-analysisd", "bin/provigil-modulesd", "bin/provigil-execd", "bin/provigil-agentlessd"];
/// The longest path accepted under the incoming folder.
const PATH_MAX: usize = 4096;
/// The exit status of a program that could not run.
const NOT_RUN: i32 = 127;

/// `<incoming>/<name>`; None for a name that leaves the folder or a path that is too long.
fn incoming(name: &str) -> Option<String> {
    if provigil_fileop::ref_parent_folder(name) {
        return None;
    }
    let p = format!("{INCOMING}/{name}");
    (p.len() <= PATH_MAX).then_some(p)
}

/// `ok ` and the JSON (with two spaces, as answers always had).
fn ok_json(j: Json) -> Vec<u8> {
    [b"ok  ".as_slice(), &j.print_unformatted()].concat()
}

impl Execd {
    /// The answer to one request.
    pub fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        let request = String::from_utf8_lossy(&request[..request.iter().position(|&c| c == 0).unwrap_or(request.len())]).into_owned();
        let (command, args) = match request.split_once(' ') {
            Some((c, a)) => (c, Some(a)),
            None => (request.as_str(), None),
        };
        let needs = |what: &str| {
            self.log.debug(format!("WCOM {what} needs arguments."));
            format!("err WCOM {what} needs arguments")
        };
        let text = match command {
            "unmerge" => match args {
                None => needs("unmerge"),
                Some(a) => self.unmerge(a),
            },
            "uncompress" => match args.map(|a| a.split_once(' ')) {
                None => needs("uncompress"),
                Some(None) => {
                    self.log.debug("Bad WCOM uncompress message.");
                    "err Too few commands".into()
                }
                Some(Some((from, to))) => self.uncompress(from, to),
            },
            "restart" | "restart-wazuh" => self.restart(false),
            "reload" => self.restart(true),
            "lock_restart" => self.lock_restart(args),
            "getconfig" => match args {
                None => needs("getconfig"),
                Some(section) => return self.getconfig(section),
            },
            "check-manager-configuration" => return self.check_configuration(),
            other => {
                self.log.debug(format!("WCOM Unrecognized command '{other}'."));
                "err Unrecognized command".into()
            }
        };
        text.into_bytes()
    }

    /// Splits a merged file of the incoming folder into its files.
    fn unmerge(&self, name: &str) -> String {
        let Some(path) = incoming(name) else {
            self.log.error("At WCOM unmerge: Invalid file name");
            return "err Invalid file name".into();
        };
        let (abs, dir) = (self.home.join(&path), self.home.join(INCOMING));
        if !provigil_fileop::unmerge_files_mode(&abs.to_string_lossy(), Some(&dir.to_string_lossy()), false).0 {
            self.log.error(format!("At WCOM unmerge: Error unmerging file '{path}.'"));
            return "err Cannot unmerge file".into();
        }
        "ok ".into()
    }

    /// Unpacks a gzip file of the incoming folder (other data is copied as it is) and removes it.
    fn uncompress(&self, from: &str, to: &str) -> String {
        let (Some(src), Some(dst)) = (incoming(from), incoming(to)) else {
            self.log.error("At WCOM uncompress: Invalid file name");
            return "err Invalid file name".into();
        };
        let Ok(mut input) = std::fs::File::open(self.home.join(&src)) else {
            self.log.error(format!("At WCOM uncompress: Unable to open '{src}'"));
            return "err Unable to open source".into();
        };
        let Ok(mut output) = std::fs::File::create(self.home.join(&dst)) else {
            self.log.error(format!("At WCOM uncompress: Unable to open '{dst}'"));
            return "err Unable to open target".into();
        };
        let mut raw = Vec::new();
        let read = input.read_to_end(&mut raw).is_ok();
        let data = if raw.starts_with(&[0x1f, 0x8b]) {
            let mut d = Vec::new();
            flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut d).ok().map(|_| d)
        } else {
            read.then_some(raw)
        };
        let Some(data) = data else {
            self.log.error(format!("At WCOM uncompress: Unable to read '{src}'"));
            return "err Unable to read source".into();
        };
        if output.write_all(&data).is_err() {
            self.log.error(format!("At WCOM uncompress: Unable to write '{dst}'"));
            return "err Unable to write target".into();
        }
        drop(input);
        let _ = std::fs::remove_file(self.home.join(&src));
        "ok ".into()
    }

    /// Restarts (or reloads) the manager unless restarts are locked.
    fn restart(&self, reload: bool) -> String {
        let locked = self.restart_lock.load(Ordering::SeqCst) - now();
        if locked > 0 {
            self.log.info(format!("Agent auto-restart locked for {locked} seconds."));
            return "ok ".into();
        }
        let script = "active-response/bin/restart.sh";
        let argv: Vec<&str> = if self.home.join(script).exists() {
            if reload {
                vec![script, "agent", "reload"]
            } else {
                vec![script, "agent"]
            }
        } else {
            vec!["bin/provigil-control", if reload { "reload" } else { "restart" }]
        };
        self.run_detached(&argv);
        "ok ".into()
    }

    /// Refuses restarts for a while: the given seconds, at most `execd.max_restart_lock`; -1 or
    /// more than that means the maximum.
    fn lock_restart(&self, args: Option<&str>) -> String {
        let max = match self.opts.int("execd", "max_restart_lock", 600, 0, 3600) {
            Ok(m) => m as i32,
            Err(e) => {
                self.log.critical(e);
                std::process::exit(1);
            }
        };
        self.max_restart_lock.store(max, Ordering::SeqCst);
        let mut seconds = args.map(atoi).unwrap_or(-2);
        let text = if seconds < -1 {
            "err Invalid timeout".to_string()
        } else {
            if seconds == -1 || seconds > max {
                if seconds > max {
                    self.log.warn("Timeout exceeds the maximum allowed.");
                }
                seconds = max;
            }
            "ok ".to_string()
        };
        self.restart_lock.store(now() + seconds as i64, Ordering::SeqCst);
        text
    }

    fn getconfig(&self, section: &str) -> Vec<u8> {
        match section {
            "active-response" => return ok_json(self.settings_json()),
            "logging" => {
                let mut l = Json::object();
                l.add("plain", Json::string("yes")).add("json", Json::string("no"));
                let mut root = Json::object();
                root.add("logging", l);
                return ok_json(root);
            }
            "internal" => return ok_json(self.options_json()),
            "cluster" if provigil_ipc::local::connect(&self.home.join(CLUSTER_SOCKET)).is_err() => {
                return b"err Unable to connect with socket. The component might be disabled".to_vec();
            }
            _ => {}
        }
        self.log.debug(format!("At WCOM getconfig: Could not get '{section}' section"));
        b"err Could not get requested section".to_vec()
    }

    /// Runs each manager program with `-t`: `{"error":0,"message":"ok"}`, or the exit status and
    /// what went wrong.
    fn check_configuration(&self) -> Vec<u8> {
        let mut status = 0;
        let mut message: Option<String> = None;
        if provigil_daemon::xml::read_file(&self.home.join(CONF)).is_err() {
            status = NOT_RUN;
        } else {
            for program in PROGRAMS {
                let command = format!("{program} -t");
                let Captured { result, output, status: exit } = capture(&self.home, &command, 2000);
                status = exit.unwrap_or(0);
                match output.filter(|_| result >= 0) {
                    None => {
                        if status == NOT_RUN {
                            self.log.warn(format!("Path is invalid or file has insufficient permissions. {command}"));
                        } else {
                            self.log.warn(format!("Error executing [{command}]"));
                        }
                        message = Some(format!("Error executing {command} - ({status})"));
                        break;
                    }
                    Some(out) => {
                        let mut out = String::from_utf8_lossy(&out).into_owned();
                        if !out.is_empty() {
                            if out.ends_with('\n') {
                                out.pop();
                            }
                            match message.as_mut() {
                                Some(m) => {
                                    m.push(' ');
                                    m.push_str(&out);
                                }
                                None => message = Some(out),
                            }
                        }
                    }
                }
                if status != 0 {
                    break;
                }
            }
        }
        let mut j = Json::object();
        j.add("error", Json::number(status as f64));
        let text = if status != 0 { cut(message.as_deref().unwrap_or("(null)"), KEY_ROOM - 27) } else { "ok".into() };
        j.add("message", Json::string(text));
        j.print_unformatted()
    }

    /// Serves `queue/sockets/com`, one request per connection, one connection at a time.
    pub fn serve(&self) {
        self.log.debug("Local requests thread ready");
        let path = self.home.join(COM_SOCKET);
        let listener = match provigil_ipc::local::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                self.log.error(format!("Unable to bind to socket '{COM_SOCKET}': ({}) {}.", errno(&e), strerror(&e)));
                return;
            }
        };
        for peer in listener.incoming() {
            let mut peer = match peer {
                Ok(p) => p,
                Err(e) => {
                    self.log.error(format!("At wcom_main(): accept(): {}", strerror(&e)));
                    continue;
                }
            };
            // a client that sends nothing cannot hold the service
            let _ = peer.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            match provigil_ipc::framing::recv(&mut peer, provigil_ipc::MAX_MESSAGE) {
                Ok(Some(m)) if !m.is_empty() => {
                    let answer = self.dispatch(&m);
                    let _ = provigil_ipc::framing::send(&mut peer, &answer);
                }
                Ok(_) => self.log.debug("Empty message from local client."),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => self.log.error("At wcom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
                Err(e) => self.log.error(format!("At wcom_main(): OS_RecvSecureTCP(): {}", strerror(&e))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execd(home: &std::path::Path) -> Execd {
        Execd::new(home, std::sync::Arc::new(provigil_daemon::Log::null()), provigil_daemon::Options::read(home))
    }

    #[test]
    fn cluster_restart_and_check() {
        let h = tempfile::tempdir().unwrap();
        let ex = execd(h.path());
        assert_eq!(ex.dispatch(b"getconfig cluster"), b"err Unable to connect with socket. The component might be disabled");
        assert_eq!(ex.dispatch(b"getconfig internal"), br#"ok  {"internal":{"execd":{"request_timeout":0,"max_restart_lock":0}}}"#);
        ex.read_options().unwrap();
        assert_eq!(ex.dispatch(b"getconfig internal"), br#"ok  {"internal":{"execd":{"request_timeout":60,"max_restart_lock":600}}}"#);
        assert_eq!(ex.dispatch(b"getconfig logging"), br#"ok  {"logging":{"plain":"yes","json":"no"}}"#);
        // restarts are refused while locked
        assert_eq!(ex.dispatch(b"lock_restart 30"), b"ok ");
        assert_eq!(ex.dispatch(b"restart"), b"ok ");
        assert!(ex.detached.lock().unwrap().is_empty());
        // no settings file: error 127
        assert_eq!(ex.dispatch(b"check-manager-configuration"), br#"{"error":127,"message":"(null)"}"#);
        std::fs::create_dir_all(h.path().join("etc")).unwrap();
        std::fs::write(h.path().join("etc/ossec.conf"), "<ossec_config/>").unwrap();
        let a = String::from_utf8(ex.dispatch(b"check-manager-configuration")).unwrap();
        assert!(a.starts_with(r#"{"error":127,"message":"Error executing bin/provigil-db -t - (127)"#), "{a}");
    }
}
