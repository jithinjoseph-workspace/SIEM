//! The service's settings in `etc/ossec.conf` (`<active-response>`: `disabled`, the first
//! `repeated_offenders`) and the internal options, and their JSON for `getconfig`.

use std::sync::atomic::Ordering;

use provigil_daemon::xml;
use provigil_json::Json;

use crate::{atoi, Execd};

/// What reading the settings found.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Enabled,
    Disabled,
    /// A bad value (already logged).
    Invalid,
}

impl Execd {
    /// Reads `<active-response>` from `conf` (relative to the home folder). Err: the file is not
    /// readable XML (the text to log as critical).
    pub fn read_settings(&self, conf: &str) -> Result<Outcome, String> {
        self.disabled.store(false, Ordering::SeqCst);
        let roots = xml::read_file(&self.home.join(conf)).map_err(|e| format!("(1226): Error reading XML file '{conf}': {} (line {}).", e.message, e.line))?;
        match xml::first_content(&roots, &["ossec_config", "active-response", "disabled"]) {
            Some("yes") => self.disabled.store(true, Ordering::SeqCst),
            Some("no") | None => {}
            Some(other) => {
                self.log.error(format!("(1235): Invalid value for element 'disabled': {other}."));
                return Ok(Outcome::Invalid);
            }
        }
        // the first <repeated_offenders> of any <active-response>, in any root
        let first = roots
            .iter()
            .flat_map(|r| r.children.iter().filter(|c| c.name == "active-response"))
            .find_map(|ar| ar.children.iter().find(|c| c.name == "repeated_offenders"));
        if let Some(r) = first {
            let Some(parts) = provigil_regex::str_break(',', &r.content, 5) else {
                self.log.error(format!("(1235): Invalid value for element 'repeated_offenders': {}.", r.content));
                return Ok(Outcome::Invalid);
            };
            let mut list = self.offenders.lock().unwrap_or_else(|e| e.into_inner());
            for p in parts {
                let t = p.trim_start_matches([' ', '\t']);
                if t.is_empty() {
                    continue;
                }
                list.push(atoi(t));
                self.log.info(format!("Adding offenders timeout: {} (for #{})", atoi(t), list.len()));
                if list.len() >= 6 {
                    break;
                }
            }
        }
        Ok(if self.disabled.load(Ordering::SeqCst) { Outcome::Disabled } else { Outcome::Enabled })
    }

    /// The offender timeouts in effect: up to the first zero.
    pub fn offender_minutes(&self) -> Vec<i32> {
        self.offenders.lock().unwrap_or_else(|e| e.into_inner()).iter().copied().take_while(|&m| m != 0).collect()
    }

    /// Reads the internal options the service reports (`execd.request_timeout`,
    /// `execd.max_restart_lock`). Err: a bad value (the text to log as critical).
    pub fn read_options(&self) -> Result<(), String> {
        self.request_timeout.store(self.opts.int("execd", "request_timeout", 60, 1, 3600)? as i32, Ordering::SeqCst);
        self.max_restart_lock.store(self.opts.int("execd", "max_restart_lock", 600, 0, 3600)? as i32, Ordering::SeqCst);
        Ok(())
    }

    /// `{"active-response":{"disabled":..,"repeated_offenders":[..]}}`
    pub fn settings_json(&self) -> Json {
        let mut ar = Json::object();
        ar.add("disabled", Json::string(if self.disabled.load(Ordering::SeqCst) { "yes" } else { "no" }));
        let minutes = self.offender_minutes();
        if !minutes.is_empty() {
            ar.add("repeated_offenders", Json::Array(minutes.iter().map(|&m| Json::number(m as f64)).collect()));
        }
        let mut root = Json::object();
        root.add("active-response", ar);
        root
    }

    /// `{"internal":{"execd":{"request_timeout":..,"max_restart_lock":..}}}`
    pub fn options_json(&self) -> Json {
        let mut e = Json::object();
        e.add("request_timeout", Json::number(self.request_timeout.load(Ordering::SeqCst) as f64));
        e.add("max_restart_lock", Json::number(self.max_restart_lock.load(Ordering::SeqCst) as f64));
        let mut internal = Json::object();
        internal.add("execd", e);
        let mut root = Json::object();
        root.add("internal", internal);
        root
    }
}
