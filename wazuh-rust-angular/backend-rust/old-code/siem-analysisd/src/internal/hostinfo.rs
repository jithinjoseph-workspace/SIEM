//! Host information decoder (analysisd/decoders/hostinfo.c): `Host: <ip>,
//! <ports>` events from nmap-like tools are compared with the last ports
//! recorded for the IP in `queue/fts/hostinfo`; unchanged hosts are dropped,
//! new and changed ones are appended and decoded as `hostinfo_new` /
//! `hostinfo_modified`.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::daemon::Env;
use crate::decoders::Decoders;
use crate::event::Event;
use crate::internal::InternalDecoders;

/// `HOSTINFO_MOD`
pub const HOSTINFO_MOD: &str = "hostinfo_modified";
/// `HOSTINFO_NEW`
pub const HOSTINFO_NEW: &str = "hostinfo_new";
/// `HOSTINFO_FILE`
pub const HOSTINFO_FILE: &str = "queue/fts/hostinfo";
const OS_MAXSTR: usize = 65536;
const ERR: &[u8] = b"Error handling host information database.";

/// The decoder's process-wide state (`hi_err`, `_hi_fp`).
#[derive(Debug)]
pub struct Hostinfo {
    err: i32,
    file: Option<PathBuf>,
}

impl Hostinfo {
    /// `HostinfoInit` (the file part): open `queue/fts/hostinfo` read/write,
    /// creating it when missing.
    pub fn init(home: &Path, env: &mut dyn Env) -> Hostinfo {
        let path = home.join(HOSTINFO_FILE);
        let r = std::fs::OpenOptions::new().read(true).write(true).open(&path).or_else(|_| {
            std::fs::File::create(&path)?;
            std::fs::OpenOptions::new().read(true).write(true).open(&path)
        });
        match r {
            Ok(_) => Hostinfo { err: 0, file: Some(path) },
            Err(e) => {
                let (n, t) = crate::logmsg::errno_text(&e);
                env.log("ERROR", format!("(1103): Could not open file '{HOSTINFO_FILE}' due to [({n})-({t})].").as_bytes());
                Hostinfo { err: 0, file: None }
            }
        }
    }

    /// `DecodeHostinfo`: false when the event goes no further.
    pub fn decode(&mut self, env: &mut dyn Env, decs: &mut Decoders, ids: &InternalDecoders, ev: &mut Event) -> bool {
        if self.err > 30 {
            env.log("ERROR", b"Too many errors handling host information db. Ignoring it.");
            return false;
        }
        let Some(path) = self.file.clone() else {
            env.log("ERROR", ERR);
            self.err += 1;
            return false;
        };
        // strncpy(buffer, lf->log, OS_MAXSTR)
        let log = ev.log();
        let buffer = &log[..log.len().min(OS_MAXSTR)];
        // __go_after(buffer, "Host: ")
        const HOST: &[u8] = b"Host: ";
        if buffer.len() <= HOST.len() || !buffer.starts_with(HOST) {
            env.log("ERROR", ERR);
            self.err += 1;
            return false;
        }
        let rest = &buffer[HOST.len()..];
        let Some(comma) = rest.iter().position(|&c| c == b',') else {
            env.log("ERROR", ERR);
            self.err += 1;
            return false;
        };
        let portss = &rest[comma + 1..];
        let mut ip = &rest[..comma];
        if let Some(sp) = ip.iter().position(|&c| c == b' ') {
            ip = &ip[..sp];
        }
        let data = std::fs::read(&path).unwrap_or_default();
        let mut changed = false;
        // fgets(_hi_buf, OS_MAXSTR - 1, fp): pieces of at most 65534 bytes
        let mut pos = 0;
        while pos < data.len() {
            let max = OS_MAXSTR - 2;
            let end = match data[pos..].iter().take(max).position(|&c| c == b'\n') {
                Some(p) => pos + p + 1,
                None => (pos + max).min(data.len()),
            };
            let mut line = &data[pos..end];
            pos = end;
            // the buffer is a C string
            if let Some(z) = line.iter().position(|&c| c == 0) {
                line = &line[..z];
            }
            if line.first() == Some(&b'\n') || line.first() == Some(&b'#') {
                continue;
            }
            if let Some(nl) = line.iter().position(|&c| c == b'\n') {
                line = &line[..nl];
            }
            if line.starts_with(ip) {
                if &line[ip.len()..] == portss {
                    return false;
                }
                changed = true;
            }
        }
        let mut entry = ip.to_vec();
        entry.extend_from_slice(portss);
        entry.push(b'\n');
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
            let _ = f.write_all(&entry);
        }
        ev.decoder = ids.hostinfo;
        decs.infos[ids.hostinfo].id = if changed { ids.hostinfo_mod_id } else { ids.hostinfo_new_id };
        true
    }
}
