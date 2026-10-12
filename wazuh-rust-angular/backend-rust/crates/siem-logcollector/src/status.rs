//! The read positions (`files_status` and `queue/logcollector/file_status.json`)
//! with the SHA1 of the bytes read so far (`w_update_file_status`,
//! `w_initialize_file_status`, `w_save_file_status`,
//! `w_set_to_last_line_read`, `w_update_hash_node`, `w_get_hash_context`)
//! and `OS_SHA1_File_Nbytes` / `OS_SHA1_Stream`.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;

use sha1::{Digest, Sha1};
use siem_cjson::Json;

use crate::*;

/// `os_file_status_t`
#[derive(Clone)]
pub struct FileStatus {
    pub offset: i64,
    pub context: Sha1,
    /// `hash` (`os_sha1`, 40 hex digits)
    pub hash: String,
}

/// `files_status`: path -> status, in insertion order (the C hash table
/// is randomly seeded, so its order carries no meaning).
#[derive(Default)]
pub struct FileStatusTable {
    pub map: Mutex<(HashMap<String, FileStatus>, Vec<String>)>,
}

impl FileStatusTable {
    pub fn get(&self, path: &str) -> Option<FileStatus> {
        self.map.lock().unwrap().0.get(path).cloned()
    }

    /// `OSHash_Update_ex` / `OSHash_Add_ex`
    pub fn put(&self, path: &str, s: FileStatus) {
        let mut m = self.map.lock().unwrap();
        if m.0.insert(path.to_string(), s).is_none() {
            m.1.push(path.to_string());
        }
    }

    /// `OSHash_Delete_ex`
    pub fn delete(&self, path: &str) {
        let mut m = self.map.lock().unwrap();
        if m.0.remove(path).is_some() {
            m.1.retain(|p| p != path);
        }
    }
}

/// `OS_SHA1_Hexdigest` of a context (without consuming it).
pub fn hexdigest(c: &Sha1) -> String {
    c.clone().finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `OS_SHA1_Stream(c, NULL, buf)`: hashes the C string (up to its NUL).
pub fn sha1_stream(c: &mut Sha1, buf: &[u8]) {
    c.update(cstr(buf));
}

/// `OS_SHA1_File_Nbytes_with_fp_check`: the context of the first `nbytes`
/// bytes of `fname`. -1 if it cannot be opened, -2 if `fd_check` (an
/// inode) is set and does not match.
pub fn sha1_file_nbytes(lc: &Lc, fname: &str, nbytes: i64, fd_check: u64) -> Result<Sha1, i32> {
    // Windows: w_fopen_r, which reads the file index (0 when it cannot)
    #[cfg(windows)]
    let mut f = {
        let f = std::fs::File::open(fname).map_err(|_| -1)?;
        let open_fd = match crate::win::fp_info(&CFile::from_file(f.try_clone().map_err(|_| -1)?)) {
            Some(i) => i.fd as u64,
            None => {
                lc.log.debug2(format!("(1117): Error handling file '{fname}'."));
                0
            }
        };
        if fd_check != 0 && open_fd != 0 && fd_check != open_fd {
            lc.log.debug1(format!("The inode does not belong to file '{fname}'. The hash of the file will be ignored."));
            return Err(-2);
        }
        f
    };
    #[cfg(unix)]
    let mut f = std::fs::File::open(fname).map_err(|_| -1)?;
    #[cfg(unix)]
    if fd_check != 0 {
        use std::os::unix::fs::MetadataExt;
        match f.metadata() {
            Err(e) => lc.log.error(fstat_error(fname, e.raw_os_error().unwrap_or(0))),
            Ok(m) => {
                if m.ino() != fd_check {
                    lc.log.debug1(format!(
                        "The inode does not belong to file '{fname}'. The hash of the file will be ignored."
                    ));
                    return Err(-2);
                }
            }
        }
    }
    let mut c = Sha1::new();
    let mut buf = vec![0u8; 2048];
    let mut count: i64 = 0;
    while count < nbytes {
        let want = if count + 2048 < nbytes { 2048 } else { (nbytes - count) as usize };
        let mut got = 0;
        while got < want {
            match f.read(&mut buf[got..want]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        c.update(&buf[..got]);
        count += 2048;
    }
    Ok(c)
}

/// `w_update_file_status`
pub fn update_file_status(lc: &Lc, path: &str, pos: i64, context: Sha1) -> i32 {
    let hash = hexdigest(&context);
    lc.status.put(path, FileStatus { offset: pos, context, hash });
    0
}

/// `w_get_hash_context`: the context of the bytes before `position`.
pub fn get_hash_context(lc: &Lc, lf: &Reader, position: i64) -> Option<Sha1> {
    match lc.status.get(lf.file()) {
        None => sha1_file_nbytes(lc, lf.file(), position, lf.fd).ok(),
        Some(d) => Some(d.context),
    }
}

/// `w_update_hash_node`
pub fn update_hash_node(lc: &Lc, path: &str, pos: i64) -> i32 {
    match sha1_file_nbytes(lc, path, pos, 0) {
        Ok(c) => update_file_status(lc, path, pos, c),
        Err(_) => {
            lc.log.error(format!("(1969): Failure to generate the SHA1 hash from file '{path}'"));
            -1
        }
    }
}

/// `w_set_to_pos`
pub fn set_to_pos(lc: &Lc, lf: &mut Reader, pos: i64, whence: i32) -> i64 {
    if lf.c.file.is_none() {
        return -1;
    }
    let Some(fp) = lf.fp.as_mut() else { return -1 };
    if fp.fseek(pos, whence) < 0 {
        let e = errno();
        lc.log.warn(format!("Fseek function failed due to [({e})-({})]", strerror(e)));
        lc.log.error(format!(
            "(1116): Could not set position in file '{}' due to [({e})-({})].",
            lf.file(),
            strerror(e)
        ));
        lf.fp = None;
        return -1;
    }
    fp.ftell()
}

/// `w_set_to_last_line_read`
pub fn set_to_last_line_read(lc: &Lc, lf: &mut Reader) -> i64 {
    let Some(file) = lf.c.file.clone() else { return 0 };
    let Some(data) = lc.status.get(&file) else {
        set_to_pos(lc, lf, 0, 2);
        let pos = lf.fp.as_ref().map(|f| f.ftell()).unwrap_or(-1);
        if update_hash_node(lc, &file, pos) == -1 {
            lc.log.error(format!("(1299): Failure to update '{file}' to 'file_status' hash table"));
        }
        return 0;
    };
    let size = match lf.fp.as_ref().and_then(|f| f.file()).map(|f| f.metadata()) {
        Some(Ok(m)) => m.len() as i64,
        Some(Err(e)) => {
            lc.log.error(fstat_error(&file, e.raw_os_error().unwrap_or(0)));
            return -1;
        }
        None => return -1,
    };
    let Ok(ctx) = sha1_file_nbytes(lc, &file, data.offset, 0) else {
        lc.log.error(format!("(1969): Failure to generate the SHA1 hash from file '{file}'"));
        return -1;
    };
    // strcmp(output, data->hash): the stored hash is compared as a C string
    let result = if hexdigest(&ctx) != data.hash {
        set_to_pos(lc, lf, 0, 0)
    } else if size - data.offset > lf.c.diff_max_size {
        set_to_pos(lc, lf, 0, 2)
    } else {
        return set_to_pos(lc, lf, data.offset, 0);
    };
    if result >= 0 && update_hash_node(lc, &file, result) == -1 {
        lc.log.error(format!("(1299): Failure to update '{file}' to 'file_status' hash table"));
    }
    result
}

/// `w_save_files_status_to_cJSON`
pub fn save_to_json(lc: &Lc) -> Option<String> {
    let mut global: Option<Json> = None;
    {
        let m = lc.status.map.lock().unwrap();
        if !m.1.is_empty() {
            let mut arr = Json::array();
            for path in &m.1 {
                let d = &m.0[path];
                let mut item = Json::object();
                item.add("path", Json::string(path));
                item.add("hash", Json::string(&d.hash));
                item.add("offset", Json::string(d.offset.to_string()));
                arr.push(item);
            }
            let mut g = Json::object();
            g.add("files", arr);
            global = Some(g);
        }
    }
    if let Some(js) = crate::journal::get_status_as_json(lc) {
        global.get_or_insert_with(Json::object).add(siem_config::localfile::JOURNALD_LOG, js);
    }
    global.map(|g| g.to_string_unformatted())
}

/// `w_save_file_status`
pub fn save_file_status(lc: &Lc) {
    let Some(s) = save_to_json(lc) else { return };
    match siem_fileop::crt::TextFile::create(LOCALFILE_STATUS) {
        Ok(mut f) => {
            use std::io::Write;
            if f.write_all(s.as_bytes()).is_err() {
                let e = errno();
                lc.log.error(format!(
                    "(1110): Could not write file '{LOCALFILE_STATUS}' due to [({e})-({})].",
                    strerror(e)
                ));
            }
        }
        Err(e) => lc.exit_critical(fopen_error(LOCALFILE_STATUS, e.raw_os_error().unwrap_or(0))),
    }
}

/// `w_load_files_status`
fn load_files_status(lc: &Lc, global: &Json) {
    if let Some(files) = global.get("files") {
        for item in files.children() {
            let Some(path) = item.get("path").and_then(|p| p.as_str()).map(|s| s.into_owned()) else { continue };
            if std::fs::metadata(&path).is_err() {
                continue;
            }
            let Some(hash) = item.get("hash").and_then(|p| p.as_str()).map(|s| s.into_owned()) else { continue };
            let Some(off) = item.get("offset").and_then(|p| p.as_str()).map(|s| s.into_owned()) else { continue };
            let (v, used) = siem_config::util::strtol(&off);
            if v < 0 || used != off.len() {
                continue;
            }
            // memcpy(data->hash, hash_str, sizeof(os_sha1))
            let hash: String = hash.chars().take(40).collect();
            match sha1_file_nbytes(lc, &path, v, 0) {
                Ok(c) => lc.status.put(&path, FileStatus { offset: v, context: c, hash }),
                Err(_) => {
                    lc.log.debug1(format!("(9000): File '{path}' no longer exists."));
                    return;
                }
            }
        }
    }
    crate::journal::set_status_from_json(lc, global);
}

/// `w_initialize_file_status`
pub fn initialize_file_status(lc: &Lc) {
    match siem_fileop::crt::read_text(LOCALFILE_STATUS) {
        Ok(data) => {
            // fread(str, 1, OS_MAXSTR - 1, fd)
            let buf = &data[..data.len().min(OS_MAXSTR - 1)];
            let n = buf.len();
            if n < 1 {
                let e = errno();
                lc.log.error(format!(
                    "(1115): Could not read from file '{LOCALFILE_STATUS}' due to [({e})-({})].",
                    strerror(e)
                ));
            } else if let Some(j) = siem_cjson::parse(cstr(&buf[..n])) {
                load_files_status(lc, &j);
            }
        }
        Err(e) => {
            // errno != ENOENT (on Windows errno is GetLastError(), so a
            // missing directory, 3, is reported)
            let n = e.raw_os_error().unwrap_or(0);
            if n != 2 {
                lc.log.error(fopen_error(LOCALFILE_STATUS, n));
            }
        }
    }
}
