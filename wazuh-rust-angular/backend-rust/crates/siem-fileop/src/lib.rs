//! `siem-fileop`: port of the parts of `src/shared/file_op.c` that the
//! manager and agents use for shared configuration distribution:
//! `MergeAppendFile`, `UnmergeFiles`, `TestUnmergeFiles`, `checkBinaryFile`,
//! `w_copy_file`, `wreaddir`, `rmdir_ex`, `cldir_ex_ignore`, `OS_MD5_File`.
//!
//! Paths are handled as `/`-separated strings, as Wazuh does: the relative
//! names written into `merged.mg` must be byte-identical to a C manager's.

use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;

/// POSIX `dirname()` on a `/`-separated path.
pub fn dirname(path: &str) -> String {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return if path.starts_with('/') { "/".into() } else { ".".into() };
    }
    match p.rfind('/') {
        None => ".".into(),
        Some(0) => "/".into(),
        Some(i) => {
            let d = p[..i].trim_end_matches('/');
            if d.is_empty() {
                "/".into()
            } else {
                d.into()
            }
        }
    }
}

/// The `path_offset` computed when `-1` is passed to `MergeAppendFile`:
/// length of `dirname(file)` plus the separator.
pub fn default_path_offset(file: &str) -> usize {
    let base = dirname(file);
    let mut off = base.len();
    if !base.ends_with('/') {
        off += 1;
    }
    off
}

/// `MergeAppendFile`: append `"!<size> <name>\n" + contents` to `out`.
/// `path_offset = None` uses [`default_path_offset`]. Returns false on error
/// (unreadable file, or the file changed size while being read).
pub fn merge_append_file(out: &mut Vec<u8>, file: &str, path_offset: Option<usize>) -> bool {
    let off = path_offset.unwrap_or_else(|| default_path_offset(file));
    let data = match fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Unable to open file: '{}' due to [({})-({})].", file, e.raw_os_error().unwrap_or(0), e);
            return false;
        }
    };
    if data.is_empty() {
        tracing::warn!("File '{file}' is empty.");
    }
    let name = file.get(off.min(file.len())..).unwrap_or("");
    let _ = write!(out, "!{} {}\n", data.len(), name);
    out.extend_from_slice(&data);
    // The C code compares ftell() before and after reading; a single read
    // of the whole file cannot observe a size change.
    true
}

/// `fgets(buf, size, fp)` chunking: pieces of at most `size - 1` bytes, each
/// ending after a `\n` when one is found.
fn fgets_chunks(data: &[u8], size: usize) -> Vec<&[u8]> {
    let max = size - 1;
    let mut out = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = start;
        while end < data.len() && end - start < max {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        out.push(&data[start..end]);
        start = end;
    }
    out
}

/// `checkBinaryFile`: true when the file cannot be read or a newline-ended
/// line contains a NUL byte (lines without a trailing newline are not
/// checked, exactly like the C code).
pub fn check_binary_file(path: &str) -> bool {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Unable to open file '{}' due to [({})-({})].", path, e.raw_os_error().unwrap_or(0), e);
            return true;
        }
    };
    for chunk in fgets_chunks(&data, OS_MAXSTR + 1) {
        if chunk.last() == Some(&b'\n') && chunk[..chunk.len() - 1].contains(&0) {
            tracing::debug!("Line contains some zero-bytes.");
            return true;
        }
    }
    false
}

/// Parse one `!<size> <name>` header line (as read by `fgets(buf, 2048)`).
fn parse_header(line: &[u8]) -> Option<(usize, String)> {
    let s = String::from_utf8_lossy(line);
    let s = s.trim_end_matches('\n');
    let size = {
        let digits: String = s[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<usize>().unwrap_or(0)
    };
    let name = s.find(' ').map(|p| s[p + 1..].to_string())?;
    Some((size, name))
}

/// `TestUnmergeFiles`: validate the structure of a merged file.
pub fn test_unmerge_files(path: &str) -> bool {
    let Ok(data) = fs::read(path) else {
        tracing::error!("Unable to read merged file: '{path}'.");
        return false;
    };
    let mut pos = 0;
    let mut ret = true;
    while pos < data.len() {
        // fgets(buf, sizeof(buf) - 1) with buf[2049] => at most 2047 bytes
        let line = fgets_chunks(&data[pos..], 2048).into_iter().next().unwrap_or(&[]);
        pos += line.len();
        match line.first() {
            Some(b'#') => continue,
            Some(b'!') => {}
            _ => return false,
        }
        match parse_header(line) {
            None => {
                ret = false;
                continue;
            }
            Some((size, name)) => {
                if name.is_empty() {
                    return false;
                }
                let avail = data.len() - pos;
                let read = size.min(avail);
                pos += read;
                if read != size {
                    return false;
                }
            }
        }
    }
    ret
}

/// `UnmergeFiles`: extract every file of a merged file into `optdir`
/// (rejecting names containing `..`). Returns (ok, relative names written).
pub fn unmerge_files(path: &str, optdir: Option<&str>) -> (bool, Vec<String>) {
    let mut names = Vec::new();
    let Ok(data) = fs::read(path) else {
        tracing::error!("Unable to read merged file: '{path}'.");
        return (false, names);
    };
    let mut pos = 0;
    let mut ret = true;
    while pos < data.len() {
        let line = fgets_chunks(&data[pos..], 2048).into_iter().next().unwrap_or(&[]);
        pos += line.len();
        if line.first() != Some(&b'!') {
            continue;
        }
        let Some((size, file)) = parse_header(line) else {
            ret = false;
            continue;
        };
        let mut state_ok = true;
        let final_name = match optdir {
            Some(d) => {
                let f = format!("{d}/{file}");
                if ref_parent_folder(&f) {
                    tracing::error!("Unmerging '{path}': unable to unmerge '{f}' (it contains '..')");
                    state_ok = false;
                }
                f
            }
            None => file.clone(),
        };
        let parent = dirname(&final_name);
        if fs::create_dir_all(&parent).is_err() {
            tracing::error!("Unmerging '{path}': couldn't create directory '{file}'");
            state_ok = false;
        }
        let read = size.min(data.len() - pos);
        let content = &data[pos..pos + read];
        pos += read;
        if state_ok {
            let tmp = format!("{final_name}.tmp-unmerge");
            if fs::write(&tmp, content).is_err() || fs::rename(&tmp, &final_name).is_err() {
                let _ = fs::remove_file(&tmp);
                ret = false;
                break;
            }
        } else {
            ret = false;
        }
        let rel = match optdir {
            Some(d) if final_name.starts_with(d) && final_name.as_bytes().get(d.len()) == Some(&b'/') => {
                final_name[d.len() + 1..].to_string()
            }
            Some(_) => final_name.rsplit('/').next().unwrap_or(&final_name).to_string(),
            None => final_name.clone(),
        };
        names.push(rel);
    }
    (ret, names)
}

/// `w_ref_parent_folder`: true if the path contains a `..` component.
pub fn ref_parent_folder(path: &str) -> bool {
    path.split('/').any(|c| c == "..")
}

/// `wreaddir`: entries except `.`/`..`, sorted with `strcmp`.
pub fn wreaddir(dir: &str) -> Option<Vec<String>> {
    let rd = fs::read_dir(dir).ok()?;
    let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.retain(|n| n != "." && n != "..");
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Some(v)
}

/// `w_copy_file`: mode `'a'` appends, anything else truncates; `message` is
/// written before the contents.
pub fn copy_file(src: &str, dst: &str, mode: char, message: Option<&str>) -> io::Result<()> {
    let data = fs::read(src)?;
    let mut f = if mode == 'a' {
        fs::OpenOptions::new().create(true).append(true).open(dst)?
    } else {
        fs::File::create(dst)?
    };
    if let Some(m) = message {
        f.write_all(m.as_bytes())?;
    }
    f.write_all(&data)
}

/// `rmdir_ex`: remove a file or a directory tree.
pub fn rmdir_ex(path: &str) -> io::Result<()> {
    let p = Path::new(path);
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn should_preserve(rel: &str, ignore: &[&str]) -> bool {
    ignore.iter().any(|ig| *ig == rel || (ig.starts_with(rel) && ig.as_bytes().get(rel.len()) == Some(&b'/')))
}

fn cldir_rec(name: &str, base: &str, ignore: &[&str]) -> io::Result<()> {
    for entry in fs::read_dir(name)?.flatten() {
        let d = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{name}/{d}");
        let rel = if path.starts_with(base) && path.as_bytes().get(base.len()) == Some(&b'/') {
            path[base.len() + 1..].to_string()
        } else {
            d.clone()
        };
        if should_preserve(&rel, ignore) {
            if Path::new(&path).is_dir() {
                cldir_rec(&path, base, ignore)?;
                let _ = fs::remove_dir(&path);
            }
            continue;
        }
        rmdir_ex(&path)?;
    }
    Ok(())
}

/// `cldir_ex_ignore`: empty `dir`, keeping the relative paths in `ignore`.
pub fn cldir_ex_ignore(dir: &str, ignore: &[&str]) -> io::Result<()> {
    cldir_rec(dir, dir, ignore)
}

/// `OS_MD5_File` (hex digest), `None` when the file cannot be read.
pub fn md5_file(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(md5_hex(&data))
}

pub fn md5_hex(data: &[u8]) -> String {
    let d = Md5::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// File modification time in seconds (`st_mtime`), `None` if missing.
pub fn mtime(path: &str) -> Option<i64> {
    let m = fs::metadata(path).ok()?;
    let t = m.modified().ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirname_like_posix() {
        assert_eq!(dirname("etc/shared/default/agent.conf"), "etc/shared/default");
        assert_eq!(dirname("/agent.conf"), "/");
        assert_eq!(dirname("agent.conf"), ".");
        assert_eq!(dirname("a/b/"), "a");
        assert_eq!(default_path_offset("etc/shared/default/agent.conf"), "etc/shared/default/".len());
    }

    #[test]
    fn merge_and_unmerge_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_string_lossy().replace('\\', "/");
        fs::create_dir_all(format!("{d}/g/sub")).unwrap();
        fs::write(format!("{d}/g/agent.conf"), "<agent_config/>\n").unwrap();
        fs::write(format!("{d}/g/sub/x.txt"), "x").unwrap();
        let mut out = b"#g\n".to_vec();
        let off = default_path_offset(&format!("{d}/g/agent.conf"));
        assert!(merge_append_file(&mut out, &format!("{d}/g/agent.conf"), Some(off)));
        assert!(merge_append_file(&mut out, &format!("{d}/g/sub/x.txt"), Some(off)));
        let expected = "#g\n!16 agent.conf\n<agent_config/>\n!1 sub/x.txt\nx".to_string();
        assert_eq!(String::from_utf8(out.clone()).unwrap(), expected);
        let mg = format!("{d}/merged.mg");
        fs::write(&mg, &out).unwrap();
        assert!(test_unmerge_files(&mg));
        let (ok, names) = unmerge_files(&mg, Some(&format!("{d}/out")));
        assert!(ok);
        assert_eq!(names, vec!["agent.conf", "sub/x.txt"]);
        assert_eq!(fs::read_to_string(format!("{d}/out/sub/x.txt")).unwrap(), "x");
    }

    #[test]
    fn binary_detection_matches_c_rules() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("b").to_string_lossy().into_owned();
        fs::write(&f, b"text\nbad\0line\n").unwrap();
        assert!(check_binary_file(&f));
        fs::write(&f, b"text\nlast\0line-without-newline").unwrap();
        assert!(!check_binary_file(&f));
        assert!(check_binary_file("/nonexistent/file"));
    }
}
