use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use thiserror::Error;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Ciphertext too short (minimum 16 bytes for IV)")]
    CiphertextTooShort,
    #[error("Decryption failed / padding error")]
    DecryptionFailed,
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
/// Format: [16 bytes IV][AES-256-CBC ciphertext]
pub fn encrypt_aes256_cbc(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypts [16 bytes IV][AES-256-CBC ciphertext] using AES-256-CBC with PKCS#7 unpadding.
pub fn decrypt_aes256_cbc(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 16 + 16 {
        return Err(CryptoError::CiphertextTooShort);
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = [42u8; 32];
        let original_msg = b"#!1001:1:syscheck:/etc/shadow modified md5=e10adc3949ba59abbe56e057f20f883e";

        let encrypted = encrypt_aes256_cbc(&key, original_msg);
        assert_ne!(encrypted, original_msg);
        assert!(encrypted.len() >= 16 + original_msg.len());

        let decrypted = decrypt_aes256_cbc(&key, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, original_msg);
    }

    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let msg = b"Secret message from agent 001";

        let encrypted = encrypt_aes256_cbc(&key1, msg);
        let res = decrypt_aes256_cbc(&key2, &encrypted);
        assert!(res.is_err());
    }
}
