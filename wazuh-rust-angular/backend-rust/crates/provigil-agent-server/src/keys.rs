//! The agents' secret keys as `ndr.agent_keys` keeps them: AES-256-GCM under a key derived from
//! `AGENT_KEYS_SECRET`, `nonce || ciphertext+tag` in hex. The plain text is a key line.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

pub type Cipher = LessSafeKey;

pub fn cipher(secret: &str) -> Option<LessSafeKey> {
    let k = Sha256::digest(secret.trim().as_bytes());
    Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).ok()?))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn encrypt(c: &LessSafeKey, plain: &str) -> Option<String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).ok()?;
    let mut buf = plain.as_bytes().to_vec();
    c.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf).ok()?;
    Some(format!("{}{}", hex(&nonce), hex(&buf)))
}

pub fn decrypt(c: &LessSafeKey, enc: &str) -> Option<String> {
    let raw = unhex(enc)?;
    if raw.len() < NONCE_LEN {
        return None;
    }
    let (n, ct) = raw.split_at(NONCE_LEN);
    let mut buf = ct.to_vec();
    let plain = c.open_in_place(Nonce::try_assume_unique_for_key(n).ok()?, Aad::empty(), &mut buf).ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

/// A key line, `<id> <name> <allowed address> <key>`: (id, allowed address, key).
pub fn parse_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut p = line.split_whitespace();
    let (id, _name, ip, key) = (p.next()?, p.next()?, p.next()?, p.next()?);
    Some((id, ip, key))
}

/// Constant-time comparison (the time does not reveal how much of a key matched).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_line() {
        let c = cipher("test-secret").unwrap();
        let line = "001 web any 0123456789abcdef";
        let e = encrypt(&c, line).unwrap();
        assert!(!e.contains("web"));
        assert_eq!(decrypt(&c, &e).as_deref(), Some(line));
        assert_eq!(decrypt(&cipher("other").unwrap(), &e), None);
        assert_eq!(parse_line(line), Some(("001", "any", "0123456789abcdef")));
        assert_eq!(parse_line("001 web"), None);
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac") && !ct_eq(b"ab", b"abc"));
    }
}
