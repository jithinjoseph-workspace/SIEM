//! Port of `src/remoted/shared_download.c`: groups whose shared files are
//! downloaded from URLs listed in `etc/shared/files.yml`:
//!
//! ```yaml
//! groups:
//!   my_group:
//!     files:
//!       agent.conf: https://example.com/agent.conf
//!       merged.mg: https://example.com/merged.mg   # optional, whole bundle
//!     poll: 15
//! ```

use crate::keystore::{file_stamp, FileStamp};
use std::collections::HashMap;
use std::sync::Mutex;

pub const W_SHARED_YAML_FILE: &str = "files.yml";

#[derive(Debug, Clone, Default)]
pub struct RemoteFile {
    pub name: String,
    pub url: String,
}

/// `remote_files_group`
#[derive(Debug, Clone, Default)]
pub struct RemoteGroup {
    pub name: String,
    pub files: Vec<RemoteFile>,
    pub poll: i64,
    pub merge_file_index: Option<usize>,
}

#[derive(Debug, Default)]
struct Runtime {
    current_polling_time: i64,
    merged_is_downloaded: bool,
}

/// Downloads a URL to a local path (`wurl_request`).
pub trait Downloader: Send + Sync {
    fn download(&self, url: &str, dest: &str) -> Result<(), String>;
}

/// Blocking HTTP(S) downloader.
pub struct HttpDownloader;

impl Downloader for HttpDownloader {
    fn download(&self, url: &str, dest: &str) -> Result<(), String> {
        let resp = reqwest::blocking::get(url).map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let bytes = resp.bytes().map_err(|e| e.to_string())?;
        if let Some(p) = std::path::Path::new(dest).parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(dest, &bytes).map_err(|e| e.to_string())
    }
}

pub struct SharedDownload {
    yaml_file: String,
    download_dir: String,
    stamp: Mutex<Option<FileStamp>>,
    groups: Mutex<HashMap<String, RemoteGroup>>,
    order: Mutex<Vec<String>>,
    runtime: Mutex<HashMap<String, Runtime>>,
    downloader: Box<dyn Downloader>,
}

/// `w_do_parsing`: structural validation of `files.yml`.
pub fn parse_yaml(text: &str, file: &str) -> Result<Vec<RemoteGroup>, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| format!("Parser error: {e}"))?;
    let mut out = Vec::new();
    let top = match doc {
        serde_yaml::Value::Null => {
            tracing::warn!("Parsing '{file}': file empty");
            return Ok(out);
        }
        serde_yaml::Value::Mapping(m) => m,
        _ => return Err("Parsing error: unexpected token".into()),
    };
    let mut seen_groups = false;
    for (k, v) in top {
        let key = k.as_str().unwrap_or_default();
        if key != "groups" {
            tracing::error!("Parsing file '{file}': unexpected identifier: '{key}'");
            continue;
        }
        if seen_groups {
            tracing::warn!("Parsing '{file}': redefinition of 'group'. Ignoring repeated sections");
            continue;
        }
        seen_groups = true;
        let serde_yaml::Value::Mapping(groups) = v else { return Err("Parsing error: unexpected token".into()) };
        for (gk, gv) in groups {
            let name = gk.as_str().ok_or("Parsing error: unexpected token")?.to_string();
            let serde_yaml::Value::Mapping(gm) = gv else { return Err("Parsing error: unexpected token".into()) };
            let mut g = RemoteGroup { name, poll: 1800, ..Default::default() };
            for (ik, iv) in gm {
                match ik.as_str() {
                    Some("files") => {
                        let serde_yaml::Value::Mapping(fm) = iv else { return Err("Parsing error: unexpected token".into()) };
                        for (fk, fv) in fm {
                            let fname = fk.as_str().unwrap_or_default().to_string();
                            let url = match fv {
                                serde_yaml::Value::String(s) => s,
                                serde_yaml::Value::Number(n) => n.to_string(),
                                _ => return Err(format!("Expected value after '{fname}' token")),
                            };
                            g.files.push(RemoteFile { name: fname, url });
                        }
                        g.merge_file_index = g.files.iter().position(|f| f.name == crate::manager::SHAREDCFG_FILENAME);
                    }
                    Some("poll") => {
                        let s = match iv {
                            serde_yaml::Value::Number(n) => n.to_string(),
                            serde_yaml::Value::String(s) => s,
                            _ => return Err("Expected value after 'poll' token".into()),
                        };
                        match s.parse::<i64>() {
                            Ok(p) if p >= 0 => g.poll = p,
                            _ => return Err(format!("Invalid poll value: {s}")),
                        }
                    }
                    _ => {}
                }
            }
            out.push(g);
        }
    }
    Ok(out)
}

impl SharedDownload {
    /// `w_init_shared_download`
    pub fn new(shared_dir: &str, download_dir: &str, downloader: Box<dyn Downloader>) -> Self {
        let s = Self {
            yaml_file: format!("{shared_dir}/{W_SHARED_YAML_FILE}"),
            download_dir: download_dir.to_string(),
            stamp: Mutex::new(None),
            groups: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            runtime: Mutex::new(HashMap::new()),
            downloader,
        };
        s.prepare_parsing();
        s
    }

    /// `w_prepare_parsing`: 1 parsed, 0 missing file, -1 parse error.
    fn prepare_parsing(&self) -> i32 {
        let st = file_stamp(&self.yaml_file);
        *self.stamp.lock().unwrap() = st;
        if st.is_none() {
            tracing::debug!("Shared configuration file not found.");
            self.groups.lock().unwrap().clear();
            self.order.lock().unwrap().clear();
            return 0;
        }
        let text = std::fs::read_to_string(&self.yaml_file).unwrap_or_default();
        match parse_yaml(&text, &self.yaml_file) {
            Ok(gs) => {
                tracing::info!("Successfully parsed of yaml file: {}", self.yaml_file);
                let mut m = self.groups.lock().unwrap();
                let mut o = self.order.lock().unwrap();
                m.clear();
                o.clear();
                for g in gs {
                    o.push(g.name.clone());
                    m.entry(g.name.clone()).or_insert(g);
                }
                1
            }
            Err(e) => {
                tracing::error!("{e}");
                -1
            }
        }
    }

    /// `w_yaml_file_has_changed`
    pub fn has_changed(&self) -> bool {
        file_stamp(&self.yaml_file) != *self.stamp.lock().unwrap()
    }

    /// `w_yaml_file_update_structs`
    pub fn update_structs(&self) {
        tracing::info!("File '{}' changed. Reloading data", self.yaml_file);
        self.runtime.lock().unwrap().clear();
        self.prepare_parsing();
    }

    /// `w_yaml_create_groups`: make sure each remote group has a directory.
    pub fn create_groups(&self, shared_dir: &str) {
        for name in self.order.lock().unwrap().iter() {
            let p = format!("{shared_dir}/{name}");
            if !std::path::Path::new(&p).is_dir() {
                if let Err(e) = std::fs::create_dir_all(&p) {
                    tracing::error!("Couldn't make dir '{p}': {e}");
                }
            }
        }
    }

    /// `w_parser_get_group`
    pub fn get_group(&self, name: &str) -> Option<RemoteGroup> {
        self.groups.lock().unwrap().get(name).cloned()
    }

    /// The download part of `c_group`. Returns `merged_is_downloaded`.
    pub fn poll_group(&self, g: &RemoteGroup, merged: &str, dir: &str, group: &str, poll_interval: i32) -> bool {
        let mut rt_all = self.runtime.lock().unwrap();
        let rt = rt_all.entry(g.name.clone()).or_default();
        if rt.current_polling_time <= 0 {
            rt.current_polling_time = g.poll;
            if let Some(idx) = g.merge_file_index {
                let url = &g.files[idx].url;
                let dest = format!("{}/{}", self.download_dir, crate::manager::SHAREDCFG_FILENAME);
                tracing::debug!("Downloading shared file '{merged}' from '{url}'");
                let ok = self.downloader.download(url, &dest).is_ok();
                if !ok {
                    tracing::error!("Unable to download file '{url}'");
                }
                rt.merged_is_downloaded = ok;
                if ok {
                    if !siem_fileop::test_unmerge_files(&dest) {
                        let _ = std::fs::remove_file(&dest);
                        tracing::error!("The downloaded file '{dest}' is corrupted.");
                        return rt.merged_is_downloaded;
                    }
                    let _ = std::fs::rename(&dest, merged).or_else(|_| std::fs::copy(&dest, merged).map(|_| ()));
                }
            } else {
                for f in &g.files {
                    let dest = format!("{dir}/{group}/{}", f.name);
                    let dl = format!("{}/{}", self.download_dir, f.name);
                    tracing::debug!("Downloading shared file '{dest}' from '{}'", f.url);
                    match self.downloader.download(&f.url, &dl) {
                        Ok(()) => {
                            let _ = std::fs::rename(&dl, &dest).or_else(|_| std::fs::copy(&dl, &dest).map(|_| ()));
                        }
                        Err(e) => tracing::error!("Unable to download file '{}': {e}", f.url),
                    }
                }
            }
        } else {
            rt.current_polling_time -= poll_interval as i64;
        }
        rt.merged_is_downloaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_files_yml() {
        let y = "groups:\n  web:\n    files:\n      agent.conf: https://x/agent.conf\n      merged.mg: https://x/merged.mg\n    poll: 15\n  db:\n    files:\n      a.txt: https://x/a\n";
        let g = parse_yaml(y, "files.yml").unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].poll, 15);
        assert_eq!(g[0].merge_file_index, Some(1));
        assert_eq!(g[1].poll, 1800);
        assert!(parse_yaml("groups:\n  x:\n    poll: -1\n", "f").is_err());
    }
}
