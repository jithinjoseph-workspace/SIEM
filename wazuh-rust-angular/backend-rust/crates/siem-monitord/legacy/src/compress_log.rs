//! Log Compression Engine (`src/monitord/compress_log.c`)
//!
//! Gzip compresses rotated logs (`.gz`) and deletes uncompressed source files.

use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

/// Compresses a log file with gzip and deletes the original file upon success matching `OS_CompressLog`.
pub fn compress_log<P: AsRef<Path>>(logfile_path: P) -> io::Result<PathBuf> {
    let p = logfile_path.as_ref();
    if !p.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Log file {} not found", p.display()),
        ));
    }

    let gz_path = PathBuf::from(format!("{}.gz", p.display()));

    let input_file = File::open(p)?;
    let mut reader = BufReader::new(input_file);

    let output_file = File::create(&gz_path)?;
    let mut encoder = GzEncoder::new(output_file, Compression::default());

    let mut buf = [0u8; 16384];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        io::Write::write_all(&mut encoder, &buf[..n])?;
    }

    encoder.finish()?;

    // Remove original file upon successful compression
    fs::remove_file(p)?;

    Ok(gz_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use tempfile::tempdir;

    #[test]
    fn test_compress_log_lifecycle() {
        let dir = tempdir().unwrap();
        let log_file = dir.path().join("ossec-01.log");
        let sample_data = "2026-09-28 12:00:00 ossec: message test payload\n";
        fs::write(&log_file, sample_data).unwrap();

        let gz_path = compress_log(&log_file).unwrap();
        assert!(gz_path.exists());
        assert!(!log_file.exists()); // Original removed

        // Decompress to verify content
        let gz_f = File::open(&gz_path).unwrap();
        let mut decoder = GzDecoder::new(gz_f);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, sample_data);
    }
}
