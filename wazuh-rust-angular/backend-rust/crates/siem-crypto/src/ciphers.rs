//! Wazuh Block Ciphers: AES-256-CBC and Blowfish-CBC (`src/os_crypto/aes`, `src/os_crypto/blowfish`)
//!
//! Complete 1-to-1 parity implementation of Wazuh's symmetric encryption routines:
//! - AES-256-CBC with PKCS7 padding and Wazuh standard IV `b"FEDCBA0987654321"`
//! - Blowfish-CBC with Wazuh standard IV `[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]`

use aes::Aes256;
use blowfish::Blowfish;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use thiserror::Error;

pub const WAZUH_AES_IV: &[u8; 16] = b"FEDCBA0987654321";
pub const WAZUH_BLOWFISH_IV: &[u8; 8] = &[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid key length: expected at least {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

type BlowfishCbcEnc = Encryptor<Blowfish>;
type BlowfishCbcDec = Decryptor<Blowfish>;

/// Encrypts plaintext using AES-256-CBC with PKCS7 padding matching `encrypt_AES`.
pub fn encrypt_aes(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let key_32 = normalize_key_32(key);
    let iv_16 = normalize_iv_16(iv);

    let cipher = Aes256CbcEnc::new(&key_32.into(), &iv_16.into());
    let mut buf = vec![0u8; plaintext.len() + 16];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(plaintext);

    let res = cipher
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
        .map_err(|e| CipherError::Encryption(format!("{:?}", e)))?;

    Ok(res.to_vec())
}

/// Decrypts ciphertext using AES-256-CBC with PKCS7 padding matching `decrypt_AES`.
pub fn decrypt_aes(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let key_32 = normalize_key_32(key);
    let iv_16 = normalize_iv_16(iv);

    let cipher = Aes256CbcDec::new(&key_32.into(), &iv_16.into());
    let mut buf = vec![0u8; ciphertext.len()];

    let res = cipher
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buf)
        .map_err(|e| CipherError::Decryption(format!("{:?}", e)))?;

    Ok(res.to_vec())
}

/// Encrypts or decrypts a string/slice using AES with Wazuh default IV matching `OS_AES_Str`.
pub fn os_aes_str(input: &[u8], charkey: &str, is_encrypt: bool) -> Result<Vec<u8>, CipherError> {
    if is_encrypt {
        encrypt_aes(charkey.as_bytes(), WAZUH_AES_IV, input)
    } else {
        decrypt_aes(charkey.as_bytes(), WAZUH_AES_IV, input)
    }
}

/// Encrypts data using Blowfish-CBC (block-aligned) matching `BF_cbc_encrypt`.
pub fn encrypt_blowfish(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let iv_8 = normalize_iv_8(iv);
    let cipher = BlowfishCbcEnc::new_from_slices(key, &iv_8)
        .map_err(|e| CipherError::Encryption(format!("{:?}", e)))?;

    // Must be multiple of 8
    let rem = data.len() % 8;
    let padded_len = if rem == 0 { data.len() } else { data.len() + (8 - rem) };
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);

    let mut out = vec![0u8; padded_len];
    for (chunk_in, chunk_out) in buf.chunks_exact(8).zip(out.chunks_exact_mut(8)) {
        chunk_out.copy_from_slice(chunk_in);
    }

    let mut enc = cipher;
    for chunk in out.chunks_exact_mut(8) {
        let block = cbc::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
    }

    Ok(out)
}

/// Decrypts data using Blowfish-CBC (block-aligned) matching `BF_cbc_encrypt` (decrypt mode).
pub fn decrypt_blowfish(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    if data.len() % 8 != 0 {
        return Err(CipherError::Decryption("Data length must be multiple of 8".to_string()));
    }

    let iv_8 = normalize_iv_8(iv);
    let cipher = BlowfishCbcDec::new_from_slices(key, &iv_8)
        .map_err(|e| CipherError::Decryption(format!("{:?}", e)))?;

    let mut out = data.to_vec();
    let mut dec = cipher;
    for chunk in out.chunks_exact_mut(8) {
        let block = cbc::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        dec.decrypt_block_mut(block);
    }

    Ok(out)
}

/// Encrypts or decrypts using Blowfish with Wazuh default IV matching `OS_BF_Str`.
pub fn os_bf_str(input: &[u8], charkey: &str, is_encrypt: bool) -> Result<Vec<u8>, CipherError> {
    if is_encrypt {
        encrypt_blowfish(charkey.as_bytes(), WAZUH_BLOWFISH_IV, input)
    } else {
        decrypt_blowfish(charkey.as_bytes(), WAZUH_BLOWFISH_IV, input)
    }
}

fn normalize_key_32(key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let copy_len = key.len().min(32);
    out[..copy_len].copy_from_slice(&key[..copy_len]);
    out
}

fn normalize_iv_16(iv: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let copy_len = iv.len().min(16);
    out[..copy_len].copy_from_slice(&iv[..copy_len]);
    out
}

fn normalize_iv_8(iv: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let copy_len = iv.len().min(8);
    out[..copy_len].copy_from_slice(&iv[..copy_len]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_roundtrip() {
        let key = b"01234567890123456789012345678901";
        let msg = b"Wazuh agent encrypted message payload!";

        let encrypted = os_aes_str(msg, std::str::from_utf8(key).unwrap(), true).unwrap();
        assert_ne!(encrypted, msg);

        let decrypted = os_aes_str(&encrypted, std::str::from_utf8(key).unwrap(), false).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_blowfish_roundtrip() {
        let key = "48_char_wazuh_encryption_key_12345678901234567890";
        let msg = b"1234567812345678"; // 16 bytes (aligned)

        let encrypted = os_bf_str(msg, key, true).unwrap();
        assert_ne!(encrypted, msg);

        let decrypted = os_bf_str(&encrypted, key, false).unwrap();
        assert_eq!(decrypted, msg);
    }
}
