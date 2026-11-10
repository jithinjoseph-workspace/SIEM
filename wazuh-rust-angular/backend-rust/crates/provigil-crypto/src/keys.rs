//! client.keys text as kept by the enrolment and API side.

use crate::hashes::md5_str;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CryptoMethod {
    #[default]
    Blowfish = 0,
    Aes = 1,
}

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

/// md5hex(raw) + first 15 chars of md5hex(md5hex(name) + md5hex(id)): 47 characters.
pub fn derive_encryption_key(name: &str, id: &str, raw: &str) -> String {
    let mut k = md5_str(raw);
    k.push_str(&md5_str(&(md5_str(name) + &md5_str(id)))[..15]);
    k
}

impl ClientKey {
    pub fn new(id: String, name: String, ip: String, raw_key: String) -> ClientKey {
        ClientKey {
            encryption_key: derive_encryption_key(&name, &id, &raw_key),
            id,
            name,
            ip,
            raw_key,
            crypto_method: CryptoMethod::Blowfish,
            global_counter: 0,
            local_counter: 0,
        }
    }

    pub fn to_key_line(&self) -> String {
        format!("{} {} {} {}", self.id, self.name, self.ip, self.raw_key)
    }
}

/// Keys in file order; lookups point at the last key added with that id / name / ip.
#[derive(Debug, Clone, Default)]
pub struct KeyStore {
    pub keys: Vec<ClientKey>,
    idx: Lookups,
}

#[derive(Debug, Clone, Default)]
struct Lookups {
    by_id: HashMap<String, usize>,
    by_name: HashMap<String, usize>,
    by_ip: HashMap<String, usize>,
}

impl Lookups {
    fn add(&mut self, i: usize, k: &ClientKey) {
        self.by_id.insert(k.id.clone(), i);
        self.by_name.insert(k.name.clone(), i);
        if k.ip != "any" {
            self.by_ip.insert(k.ip.clone(), i);
        }
    }
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore::default()
    }

    pub fn load_file<P: AsRef<Path>>(p: P) -> io::Result<KeyStore> {
        let text = fs::read_to_string(p)?;
        let mut ks = KeyStore::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(k) = Self::parse_line(line) {
                ks.add_key(k);
            }
        }
        Ok(ks)
    }

    pub fn save_file<P: AsRef<Path>>(&self, p: P) -> io::Result<()> {
        let text: String = self.keys.iter().map(|k| k.to_key_line() + "\n").collect();
        fs::write(p, text)
    }

    /// `<id> <name> <ip> <key>` split on white space; extra fields ignored.
    pub fn parse_line(line: &str) -> Option<ClientKey> {
        let mut f = line.split_whitespace();
        let (id, name, ip, key) = (f.next()?, f.next()?, f.next()?, f.next()?);
        Some(ClientKey::new(id.into(), name.into(), ip.into(), key.into()))
    }

    /// 32 random bytes as 64 lower-case hex characters.
    pub fn generate_raw_key() -> String {
        hex::encode(rand::random::<[u8; 32]>())
    }

    /// Largest numeric id + 1, at least 3 digits.
    pub fn next_id(&self) -> String {
        let max = self.keys.iter().filter_map(|k| k.id.parse::<u64>().ok()).max();
        format!("{:03}", max.map_or(1, |m| m.saturating_add(1)))
    }

    pub fn add_key(&mut self, key: ClientKey) {
        self.idx.add(self.keys.len(), &key);
        self.keys.push(key);
    }

    pub fn delete_key(&mut self, id: &str) -> Option<ClientKey> {
        let removed = self.keys.remove(*self.idx.by_id.get(id)?);
        self.idx = Lookups::default();
        for (i, k) in self.keys.iter().enumerate() {
            self.idx.add(i, k);
        }
        Some(removed)
    }

    pub fn find_by_id(&self, id: &str) -> Option<&ClientKey> {
        self.idx.by_id.get(id).map(|&i| &self.keys[i])
    }

    pub fn find_by_id_mut(&mut self, id: &str) -> Option<&mut ClientKey> {
        self.idx.by_id.get(id).map(|&i| &mut self.keys[i])
    }

    pub fn find_by_name(&self, name: &str) -> Option<&ClientKey> {
        self.idx.by_name.get(name).map(|&i| &self.keys[i])
    }

    pub fn find_by_ip(&self, ip: &str) -> Option<&ClientKey> {
        self.idx.by_ip.get(ip).map(|&i| &self.keys[i])
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
