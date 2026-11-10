//! AES-256-CBC (PKCS#7) and Blowfish-CBC (zero padding) as used by the message envelope.

use aes::Aes256;
use blowfish::Blowfish;
use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

pub const PROVIGIL_AES_IV: &[u8; 16] = b"FEDCBA0987654321";
pub const PROVIGIL_BLOWFISH_IV: &[u8; 8] = &[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

/// The detail is the cipher library's own error name (for example `InvalidLength`, `UnpadError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    /// Not produced by this crate; kept for callers that match on it.
    #[error("Invalid key length: expected at least {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
}

fn enc_err(e: impl std::fmt::Debug) -> CipherError {
    CipherError::Encryption(format!("{e:?}"))
}

fn dec_err(e: impl std::fmt::Debug) -> CipherError {
    CipherError::Decryption(format!("{e:?}"))
}

/// Zero-pads or cuts `b` to `N` bytes.
fn fit<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    let n = b.len().min(N);
    a[..n].copy_from_slice(&b[..n]);
    a
}

pub fn encrypt_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<Aes256>::new(&fit::<32>(key).into(), &fit::<16>(iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(data)
}

pub fn decrypt_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CipherError> {
    cbc::Decryptor::<Aes256>::new(&fit::<32>(key).into(), &fit::<16>(iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(dec_err)
}

/// Key must be 4-56 bytes; the data is zero-padded to a multiple of 8.
pub fn encrypt_blowfish(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CipherError> {
    let enc = cbc::Encryptor::<Blowfish>::new_from_slices(key, &fit::<8>(iv)).map_err(enc_err)?;
    let mut padded = data.to_vec();
    padded.resize(data.len().div_ceil(8) * 8, 0);
    Ok(enc.encrypt_padded_vec_mut::<NoPadding>(&padded))
}

/// Data must be a multiple of 8 bytes; padding is left in place.
pub fn decrypt_blowfish(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CipherError> {
    // The length is checked before the key.
    if data.len() % 8 != 0 {
        return Err(CipherError::Decryption("Data length must be multiple of 8".into()));
    }
    let dec = cbc::Decryptor::<Blowfish>::new_from_slices(key, &fit::<8>(iv)).map_err(dec_err)?;
    dec.decrypt_padded_vec_mut::<NoPadding>(data).map_err(dec_err)
}

/// AES with a text key and the fixed IV.
pub fn os_aes_str(input: &[u8], key: &str, encrypt: bool) -> Result<Vec<u8>, CipherError> {
    if encrypt {
        Ok(encrypt_aes(input, key.as_bytes(), PROVIGIL_AES_IV))
    } else {
        decrypt_aes(input, key.as_bytes(), PROVIGIL_AES_IV)
    }
}

/// Blowfish with a text key and the fixed IV.
pub fn os_bf_str(input: &[u8], key: &str, encrypt: bool) -> Result<Vec<u8>, CipherError> {
    if encrypt {
        encrypt_blowfish(input, key.as_bytes(), PROVIGIL_BLOWFISH_IV)
    } else {
        decrypt_blowfish(input, key.as_bytes(), PROVIGIL_BLOWFISH_IV)
    }
}
