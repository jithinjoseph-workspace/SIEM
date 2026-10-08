//! Wazuh Agent Keystore Management (`src/os_crypto/shared/keys.c`)
//!
//! Handles parsing of `client.keys`, 192-bit symmetric encryption key derivation,
//! agent ID / IP fast lookup indexing, and replay counter state.

use crate::hashes::md5_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

/// Wazuh symmetric cipher method matching `crypt_method` in `sec.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoMethod {
    Blowfish = 0,
    Aes = 1,
}

impl Default for CryptoMethod {
    fn default() -> Self {
        CryptoMethod::Blowfish
    }
}

/// Represents an agent's security credentials and replay counter state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKey {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub raw_key: String,
    pub encryption_key: String,
    pub crypto_method: CryptoMethod,
    pub global_counter: u32,
    pub local_counter: u32,
}

impl ClientKey {
    /// Creates a new `ClientKey`, deriving the 192-bit symmetric encryption key.
    pub fn new(id: String, name: String, ip: String, raw_key: String) -> Self {
        let encryption_key = derive_encryption_key(&name, &id, &raw_key);
        Self {
            id,
            name,
            ip,
            raw_key,
            encryption_key,
            crypto_method: CryptoMethod::Blowfish,
            global_counter: 0,
            local_counter: 0,
        }
    }

    /// Formats as a standard `client.keys` line: `ID NAME IP KEY`.
    pub fn to_key_line(&self) -> String {
        format!("{} {} {} {}", self.id, self.name, self.ip, self.raw_key)
    }
}

/// Derives Wazuh's 192-bit symmetric encryption key matching `OS_AddKey` in `keys.c`:
/// 1. filesum1 = MD5(name)
/// 2. filesum2 = MD5(id)
/// 3. half = MD5(filesum1 + filesum2)[0..15]
/// 4. key_hash = MD5(raw_key)
/// 5. final = key_hash + half
pub fn derive_encryption_key(name: &str, id: &str, raw_key: &str) -> String {
    let sum1 = md5_str(name);
    let sum2 = md5_str(id);
    let combined = format!("{}{}", sum1, sum2);
    let sum3 = md5_str(&combined);
    let half = &sum3[..15];
    let key_hash = md5_str(raw_key);
    format!("{}{}", key_hash, half)
}

/// Wazuh agent credentials keystore matching `keystore` in `sec.h`.
#[derive(Debug, Clone, Default)]
pub struct KeyStore {
    pub keys: Vec<ClientKey>,
    id_index: HashMap<String, usize>,
    name_index: HashMap<String, usize>,
    ip_index: HashMap<String, usize>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads agent keys from a `client.keys` formatted file path.
    pub fn load_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut keystore = Self::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(key) = Self::parse_line(trimmed) {
                keystore.add_key(key);
            }
        }

        Ok(keystore)
    }

    /// Saves the current keys to a `client.keys` formatted file.
    pub fn save_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = File::create(path)?;
        for key in &self.keys {
            writeln!(file, "{}", key.to_key_line())?;
        }
        Ok(())
    }

    /// Parses a single line `id name ip raw_key`.
    pub fn parse_line(line: &str) -> Option<ClientKey> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        let id = parts[0].to_string();
        let name = parts[1].to_string();
        let ip = parts[2].to_string();
        let raw_key = parts[3].to_string();

        Some(ClientKey::new(id, name, ip, raw_key))
    }

    /// Generates a random 64-character hex raw key (256 bits).
    pub fn generate_raw_key() -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        hex::encode(bytes)
    }

    /// Generates the next sequential agent ID (e.g. "001", "002").
    pub fn next_id(&self) -> String {
        let mut max_id: u64 = 0;
        for key in &self.keys {
            if let Ok(id_num) = key.id.parse::<u64>() {
                if id_num > max_id {
                    max_id = id_num;
                }
            }
        }
        format!("{:03}", max_id + 1)
    }

    /// Adds or updates an agent key in the keystore.
    pub fn add_key(&mut self, key: ClientKey) {
        let idx = self.keys.len();
        self.id_index.insert(key.id.clone(), idx);
        self.name_index.insert(key.name.clone(), idx);
        if key.ip != "any" {
            self.ip_index.insert(key.ip.clone(), idx);
        }
        self.keys.push(key);
    }

    /// Rebuilds indices after modification.
    fn rebuild_indices(&mut self) {
        self.id_index.clear();
        self.name_index.clear();
        self.ip_index.clear();
        for (idx, key) in self.keys.iter().enumerate() {
            self.id_index.insert(key.id.clone(), idx);
            self.name_index.insert(key.name.clone(), idx);
            if key.ip != "any" {
                self.ip_index.insert(key.ip.clone(), idx);
            }
        }
    }

    /// Deletes an agent key by ID.
    pub fn delete_key(&mut self, id: &str) -> Option<ClientKey> {
        if let Some(&idx) = self.id_index.get(id) {
            let removed = self.keys.remove(idx);
            self.rebuild_indices();
            Some(removed)
        } else {
            None
        }
    }

    /// Look up agent by ID.
    pub fn find_by_id(&self, id: &str) -> Option<&ClientKey> {
        self.id_index.get(id).and_then(|idx| self.keys.get(*idx))
    }

    /// Look up agent mutably by ID.
    pub fn find_by_id_mut(&mut self, id: &str) -> Option<&mut ClientKey> {
        if let Some(&idx) = self.id_index.get(id) {
            self.keys.get_mut(idx)
        } else {
            None
        }
    }

    /// Look up agent by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ClientKey> {
        self.name_index.get(name).and_then(|idx| self.keys.get(*idx))
    }

    /// Look up agent by IP.
    pub fn find_by_ip(&self, ip: &str) -> Option<&ClientKey> {
        if ip == "any" {
            return None;
        }
        self.ip_index.get(ip).and_then(|idx| self.keys.get(*idx))
    }

    /// Returns the number of loaded keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_encryption_key() {
        let name = "agent-001";
        let id = "001";
        let raw_key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

        let enc_key = derive_encryption_key(name, id, raw_key);
        assert_eq!(enc_key.len(), 47); // 32 chars MD5 + 15 chars half

        // Deterministic
        let enc_key2 = derive_encryption_key(name, id, raw_key);
        assert_eq!(enc_key, enc_key2);
    }

    #[test]
    fn test_keystore_add_and_find() {
        let mut ks = KeyStore::new();
        let k1 = ClientKey::new("001".into(), "agent1".into(), "192.168.1.10".into(), "key1".into());
        let k2 = ClientKey::new("002".into(), "agent2".into(), "192.168.1.20".into(), "key2".into());

        ks.add_key(k1);
        ks.add_key(k2);

        assert_eq!(ks.len(), 2);
        assert_eq!(ks.find_by_id("001").unwrap().name, "agent1");
        assert_eq!(ks.find_by_ip("192.168.1.20").unwrap().id, "002");
        assert!(ks.find_by_id("999").is_none());
    }

    #[test]
    fn test_parse_line() {
        let line = "005 server-ny 10.0.0.5 8e7d6c5b4a3928170f1e2d3c4b5a6978";
        let key = KeyStore::parse_line(line).unwrap();
        assert_eq!(key.id, "005");
        assert_eq!(key.name, "server-ny");
        assert_eq!(key.ip, "10.0.0.5");
        assert_eq!(key.raw_key, "8e7d6c5b4a3928170f1e2d3c4b5a6978");
        assert_eq!(key.to_key_line(), line);
    }
}
