//! Wazuh Zlib Compression & Decompression Layer (os_zlib/os_zlib.c, os_zlib.h)
//!
//! Provides RFC 1950 Zlib compression (level 9 / Z_BEST_COMPRESSION) and decompression
//! used throughout Wazuh for wire protocol payload compression, log archives, and active response.

use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use std::io::Read;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ZlibError {
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Decompression error: {0}")]
    Decompression(String),
    #[error("Destination buffer too small (needed {needed}, available {available})")]
    BufferTooSmall { needed: usize, available: usize },
}

/// Compress byte slice using zlib with `Z_BEST_COMPRESSION` (level 9).
/// Returns vector of compressed bytes.
pub fn os_zlib_compress(src: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut encoder = ZlibEncoder::new(src, Compression::best());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| ZlibError::Compression(e.to_string()))?;
    Ok(compressed)
}

/// Decompress byte slice using zlib RFC 1950 format.
/// Returns vector of decompressed bytes.
pub fn os_zlib_uncompress(src: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut decoder = ZlibDecoder::new(src);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ZlibError::Decompression(e.to_string()))?;
    Ok(decompressed)
}

/// Buffer-oriented C API drop-in wrapper mirroring `unsigned long int os_zlib_compress(const char *src, char *dst, ...)`
/// Null-terminates on success and returns number of compressed bytes (or 0 on failure).
pub fn os_zlib_compress_into(src: &[u8], dst: &mut [u8]) -> usize {
    if dst.is_empty() {
        return 0;
    }
    match os_zlib_compress(src) {
        Ok(compressed) => {
            // Need space for data + null terminator
            if compressed.len() >= dst.len() {
                return 0;
            }
            dst[..compressed.len()].copy_from_slice(&compressed);
            dst[compressed.len()] = 0; // null-terminate as in os_zlib.c
            compressed.len()
        }
        Err(_) => 0,
    }
}

/// Buffer-oriented C API drop-in wrapper mirroring `unsigned long int os_zlib_uncompress(const char *src, char *dst, ...)`
/// Null-terminates on success and returns number of decompressed bytes (or 0 on failure).
pub fn os_zlib_uncompress_into(src: &[u8], dst: &mut [u8]) -> usize {
    if dst.is_empty() {
        return 0;
    }
    match os_zlib_uncompress(src) {
        Ok(decompressed) => {
            if decompressed.len() >= dst.len() {
                return 0;
            }
            dst[..decompressed.len()].copy_from_slice(&decompressed);
            dst[decompressed.len()] = 0; // null-terminate as in os_zlib.c
            decompressed.len()
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_STRING_1: &str = "The quick brown fox jumps over the lazy dog";
    const TEST_STRING_2: &str = "A very long message repeated many times to test high compression ratio. A very long message repeated many times to test high compression ratio.";

    #[test]
    fn test_compress_and_uncompress_roundtrip() {
        let compressed = os_zlib_compress(TEST_STRING_1.as_bytes()).unwrap();
        assert!(!compressed.is_empty());

        let decompressed = os_zlib_uncompress(&compressed).unwrap();
        assert_eq!(String::from_utf8(decompressed).unwrap(), TEST_STRING_1);
    }

    #[test]
    fn test_high_ratio_compression() {
        let raw = TEST_STRING_2.as_bytes();
        let compressed = os_zlib_compress(raw).unwrap();
        assert!(compressed.len() < raw.len(), "Compressed size should be smaller than raw");

        let decompressed = os_zlib_uncompress(&compressed).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_c_api_buffer_wrappers() {
        let mut comp_buf = vec![0u8; 512];
        let mut decomp_buf = vec![0u8; 512];

        let comp_len = os_zlib_compress_into(TEST_STRING_1.as_bytes(), &mut comp_buf);
        assert!(comp_len > 0);
        assert_eq!(comp_buf[comp_len], 0); // null-terminated

        let decomp_len = os_zlib_uncompress_into(&comp_buf[..comp_len], &mut decomp_buf);
        assert_eq!(decomp_len, TEST_STRING_1.len());
        assert_eq!(decomp_buf[decomp_len], 0); // null-terminated
        assert_eq!(&decomp_buf[..decomp_len], TEST_STRING_1.as_bytes());
    }

    #[test]
    fn test_invalid_decompression_fails() {
        let garbage = b"this is not a valid zlib stream";
        let res = os_zlib_uncompress(garbage);
        assert!(res.is_err());
    }
}
