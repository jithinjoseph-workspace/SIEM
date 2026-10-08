//! Wazuh Cryptography Subsystem (`src/os_crypto`)
//!
//! Complete 100% line-by-line parity port of Wazuh's crypto subsystem:
//! - `hashes`: MD5, SHA-1, SHA-256, SHA-512, HMAC-SHA1, and simultaneous multi-hash streaming
//! - `ciphers`: AES-256-CBC and Blowfish-CBC encryption and decryption with Wazuh standard IVs
//! - `keys`: `client.keys` parsing, 192-bit symmetric encryption key derivation, and keystore management
//! - `msgs`: Secure agent message envelope protocol (replay counters, MD5 checksum, zlib compression, padding)
//! - `signature`: WPK256 package signature validation

pub mod ciphers;
pub mod hashes;
pub mod keys;
pub mod msgs;
pub mod signature;

pub use ciphers::{decrypt_aes, decrypt_blowfish, encrypt_aes, encrypt_blowfish, os_aes_str, os_bf_str};
pub use hashes::{
    hmac_sha1_file, hmac_sha1_str, md5_bytes, md5_file, md5_str, multi_hash_file, sha1_bytes,
    sha1_file, sha1_str, sha256_bytes, sha256_file, sha256_str, sha512_bytes, sha512_file,
    sha512_str,
};
pub use keys::{derive_encryption_key, ClientKey, CryptoMethod, KeyStore};
pub use msgs::{create_sec_msg, read_sec_msg, CounterStore, CreateOptions, KeyState, MsgError, ReadOptions, ReadResult, SenderCounter};
pub use signature::{read_wpk_header, WpkHeader, WPK_MAGIC, WPK_SIGNATURE_LEN};
