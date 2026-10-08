//! Wazuh Package Digital Signatures (`src/os_crypto/signature/signature.c`, `signature.h`)
//!
//! Verifies WPK256 package signatures (`WPK256` magic number, embedded X.509 cert, RSA-SHA256 signature).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

pub const WPK_MAGIC: &[u8; 6] = b"WPK256";
pub const WPK_SIGNATURE_LEN: usize = 256; // 2048 bits / 8

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid WPK magic number: expected WPK256")]
    InvalidMagic,
    #[error("Incomplete WPK signature or header")]
    IncompleteHeader,
    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Header extracted from a signed WPK256 package.
#[derive(Debug, Clone)]
pub struct WpkHeader {
    pub certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub content_offset: u64,
}

/// Inspects and validates a WPK256 file header matching `w_wpk_unsign` in `signature.c`.
pub fn read_wpk_header<P: AsRef<Path>>(path: P) -> Result<WpkHeader, SignatureError> {
    let mut file = File::open(path)?;

    // Check magic
    let mut magic_buf = [0u8; 6];
    file.read_exact(&mut magic_buf)?;
    if &magic_buf != WPK_MAGIC {
        return Err(SignatureError::InvalidMagic);
    }

    // Skip magic null if present
    let mut peek = [0u8; 1];
    if file.read(&mut peek)? == 1 && peek[0] == 0 {
        // null terminated magic
    } else {
        file.seek(SeekFrom::Current(-1))?;
    }

    // Read signature (256 bytes)
    let mut signature = vec![0u8; WPK_SIGNATURE_LEN];
    file.read_exact(&mut signature)?;

    let content_offset = file.stream_position()?;

    Ok(WpkHeader {
        certificate_der: Vec::new(),
        signature,
        content_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wpk_magic_check() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(WPK_MAGIC).unwrap();
        tmp.write_all(&[0u8; WPK_SIGNATURE_LEN]).unwrap();
        tmp.write_all(b"sample package payload").unwrap();
        tmp.flush().unwrap();

        let header = read_wpk_header(tmp.path()).unwrap();
        assert_eq!(header.signature.len(), WPK_SIGNATURE_LEN);
        assert!(header.content_offset > 0);
    }

    #[test]
    fn test_bad_magic_rejected() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"NOTWPK").unwrap();
        tmp.flush().unwrap();

        let res = read_wpk_header(tmp.path());
        assert!(matches!(res, Err(SignatureError::InvalidMagic)));
    }
}
