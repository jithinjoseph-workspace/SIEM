//! Wazuh Cryptographic Hash Functions (`src/os_crypto/md5`, `sha1`, `sha256`, `sha512`, `hmac`, `md5_sha1_sha256`)
//!
//! Provides MD5, SHA-1, SHA-256, SHA-512, HMAC-SHA1, and simultaneous multi-hash file streaming.

use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

type HmacSha1 = Hmac<Sha1>;

/// Computes MD5 hash of a byte slice, returning 32 lowercase hex characters.
pub fn md5_str(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes MD5 hash of raw bytes.
pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes MD5 hash of a file path.
pub fn md5_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Computes SHA-1 hash of a string, returning 40 lowercase hex characters.
pub fn sha1_str(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes SHA-1 hash of raw bytes.
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-1 hash of a file path.
pub fn sha1_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha1::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Computes SHA-256 hash of a string, returning 64 lowercase hex characters.
pub fn sha256_str(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes SHA-256 hash of raw bytes.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-256 hash of a file path.
pub fn sha256_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Computes SHA-512 hash of a string, returning 128 lowercase hex characters.
pub fn sha512_str(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes SHA-512 hash of raw bytes.
pub fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-512 hash of a file path.
pub fn sha512_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Computes HMAC-SHA1 of string `text` using `key`, matching `OS_HMAC_SHA1_Str`.
pub fn hmac_sha1_str(key: &str, text: &str) -> Result<String, io::Error> {
    let mut mac = HmacSha1::new_from_slice(key.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    mac.update(text.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Computes HMAC-SHA1 of file `path` using `key`, matching `OS_HMAC_SHA1_File`.
pub fn hmac_sha1_file<P: AsRef<Path>>(key: &str, path: P) -> io::Result<String> {
    let mut mac = HmacSha1::new_from_slice(key.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        mac.update(&buffer[..n]);
    }
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Multi-hash file scanner matching `OS_MD5_SHA1_SHA256_File`.
/// Computes MD5, SHA-1, and SHA-256 simultaneously in a single streaming read pass.
/// If `max_size > 0` and the file size exceeds `max_size`, returns an `io::ErrorKind::InvalidData` error.
pub fn multi_hash_file<P: AsRef<Path>>(path: P, max_size: usize) -> io::Result<(String, String, String)> {
    let mut file = File::open(path)?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();

    let mut buffer = [0u8; 8192];
    let mut total_read = 0;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total_read += n;
        if max_size > 0 && total_read > max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File size exceeded max allowed size of {} bytes", max_size),
            ));
        }

        md5.update(&buffer[..n]);
        sha1.update(&buffer[..n]);
        sha256.update(&buffer[..n]);
    }

    Ok((
        hex::encode(md5.finalize()),
        hex::encode(sha1.finalize()),
        hex::encode(sha256.finalize()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_known_hashes() {
        let text = "hello wazuh";
        assert_eq!(md5_str(text), "3872fd77d675e4c61724d116635abae4");
        assert_eq!(sha1_str(text), "22cf5cb91bdcc0a2ca7c869aab302d6fef1c3896");
        assert_eq!(sha256_str(text), "3182bebcd21df61351ccdcc0be183680d69f2abc5933a795acd93db980561be9");
    }

    #[test]
    fn test_multi_hash_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"hello wazuh").unwrap();
        tmp.flush().unwrap();

        let (m, s1, s256) = multi_hash_file(tmp.path(), 0).unwrap();
        assert_eq!(m, "3872fd77d675e4c61724d116635abae4");
        assert_eq!(s1, "22cf5cb91bdcc0a2ca7c869aab302d6fef1c3896");
        assert_eq!(s256, "3182bebcd21df61351ccdcc0be183680d69f2abc5933a795acd93db980561be9");
    }

    #[test]
    fn test_hmac_sha1() {
        let key = "secret-key";
        let text = "authentication message";
        let hmac = hmac_sha1_str(key, text).unwrap();
        assert!(!hmac.is_empty());
        assert_eq!(hmac.len(), 40);
    }
}
