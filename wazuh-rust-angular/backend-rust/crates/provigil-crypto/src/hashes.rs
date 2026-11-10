//! Digests as raw bytes or lower-case hex.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Streams a file through any hasher.
fn file_hex<H: Write>(path: impl AsRef<Path>, mut h: H, finish: impl FnOnce(H) -> Vec<u8>) -> io::Result<String> {
    io::copy(&mut File::open(path)?, &mut h)?;
    Ok(hex::encode(finish(h)))
}

pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub fn md5_str(s: &str) -> String {
    hex::encode(md5_bytes(s.as_bytes()))
}

pub fn md5_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    file_hex(path, Md5::new(), |h| h.finalize().to_vec())
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub fn sha1_str(s: &str) -> String {
    hex::encode(sha1_bytes(s.as_bytes()))
}

pub fn sha1_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    file_hex(path, Sha1::new(), |h| h.finalize().to_vec())
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_str(s: &str) -> String {
    hex::encode(sha256_bytes(s.as_bytes()))
}

pub fn sha256_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    file_hex(path, Sha256::new(), |h| h.finalize().to_vec())
}

pub fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub fn sha512_str(s: &str) -> String {
    hex::encode(sha512_bytes(s.as_bytes()))
}

pub fn sha512_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    file_hex(path, Sha512::new(), |h| h.finalize().to_vec())
}

fn hmac_sha1(key: &str) -> io::Result<Hmac<Sha1>> {
    Hmac::<Sha1>::new_from_slice(key.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// HMAC-SHA1 of `data` with the key text's bytes (any length).
pub fn hmac_sha1_str(key: &str, data: &str) -> io::Result<String> {
    let mut m = hmac_sha1(key)?;
    m.update(data.as_bytes());
    Ok(hex::encode(m.finalize().into_bytes()))
}

pub fn hmac_sha1_file<P: AsRef<Path>>(key: &str, path: P) -> io::Result<String> {
    file_hex(path, hmac_sha1(key)?, |m| m.finalize().into_bytes().to_vec())
}

/// MD5, SHA-1 and SHA-256 of a file in one pass; `max` > 0 refuses files larger than `max` bytes.
pub fn multi_hash_file<P: AsRef<Path>>(path: P, max: usize) -> io::Result<(String, String, String)> {
    let mut f = File::open(path)?;
    let (mut md5, mut sha1, mut sha256) = (Md5::new(), Sha1::new(), Sha256::new());
    let (mut buf, mut total) = (vec![0u8; 64 * 1024], 0usize);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n;
        if max > 0 && total > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File size exceeded max allowed size of {max} bytes"),
            ));
        }
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
    }
    Ok((hex::encode(md5.finalize()), hex::encode(sha1.finalize()), hex::encode(sha256.finalize())))
}
