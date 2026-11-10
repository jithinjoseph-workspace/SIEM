//! Reads the header of a WPK upgrade package. Nothing is verified.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const WPK_MAGIC: &[u8; 6] = b"WPK256";
pub const WPK_SIGNATURE_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid WPK magic number: expected WPK256")]
    InvalidMagic,
    /// Never produced: the reader reports a short file as `Io`.
    #[error("Incomplete WPK signature or header")]
    IncompleteHeader,
    /// Never produced: nothing is verified.
    #[error("Signature verification failed")]
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpkHeader {
    pub signature: Vec<u8>,
    /// Where the package content starts: 263 with the optional NUL after the magic, 262 without.
    pub content_offset: u64,
    /// Always empty: no certificate is read.
    pub certificate_der: Vec<u8>,
}

pub fn read_wpk_header<P: AsRef<Path>>(path: P) -> Result<WpkHeader, SignatureError> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 6];
    f.read_exact(&mut magic)?;
    if &magic != WPK_MAGIC {
        return Err(SignatureError::InvalidMagic);
    }
    let mut first = [0u8; 1];
    f.read_exact(&mut first)?;
    let mut signature = vec![0u8; WPK_SIGNATURE_LEN];
    let rest = if first[0] == 0 {
        &mut signature[..]
    } else {
        signature[0] = first[0];
        &mut signature[1..]
    };
    f.read_exact(rest)?;
    let content_offset = (WPK_MAGIC.len() + WPK_SIGNATURE_LEN + usize::from(first[0] == 0)) as u64;
    Ok(WpkHeader { signature, content_offset, certificate_der: Vec::new() })
}
