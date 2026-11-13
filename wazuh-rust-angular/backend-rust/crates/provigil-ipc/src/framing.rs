//! Messages preceded by their length (u32, little endian).

use std::io::{self, Read, Write};

/// Writes one message.
pub fn send(w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(msg.len() + 4);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    w.write_all(&buf)
}

/// Reads one message: `Ok(None)` when the peer closed before a message started; an error of
/// kind `InvalidData` when the announced size is over `max`.
pub fn recv(r: &mut impl Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(hdr) as usize;
    if n > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("message of {n} bytes is over {max}")));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_limits() {
        let mut b = Vec::new();
        send(&mut b, b"hello").unwrap();
        send(&mut b, b"").unwrap();
        let mut r = &b[..];
        assert_eq!(recv(&mut r, 100).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(recv(&mut r, 100).unwrap(), Some(Vec::new()));
        assert_eq!(recv(&mut r, 100).unwrap(), None);
        let mut big = Vec::new();
        send(&mut big, &[0u8; 10]).unwrap();
        assert_eq!(recv(&mut &big[..], 5).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
