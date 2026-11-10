//! `OS_SendSecureTCP` / `OS_RecvSecureTCP` (`src/os_net/os_net.c`): every
//! message is preceded by its length as a 4-byte little-endian integer.
//! Agents use it on TCP 1514, and daemons use it on local stream sockets.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("message of {0} bytes exceeds the limit of {1}")]
    TooBig(usize, usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Prefix `payload` with its little-endian length.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 4);
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// `OS_SendSecureTCP`
pub async fn send<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    w.write_all(&encode(payload)).await?;
    w.flush().await?;
    Ok(())
}

/// `OS_RecvSecureTCP`. Returns `Closed` when the peer closes before a header.
pub async fn recv<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, FrameError> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_le_bytes(hdr) as usize;
    if n > max {
        return Err(FrameError::TooBig(n, max));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Incremental decoder used by remoted's `nb_recv`: feed bytes as they
/// arrive and take every complete message.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received bytes.
    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Next complete message. `Err(TooBig)` mirrors `nb_recv` returning -2
    /// (the caller closes the connection).
    pub fn next_frame(&mut self, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if n > max {
            return Err(FrameError::TooBig(n, max));
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        let msg = self.buf[4..4 + n].to_vec();
        self.buf.drain(..4 + n);
        Ok(Some(msg))
    }

    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_handles_split_and_batched_frames() {
        let mut d = FrameDecoder::new();
        let mut wire = encode(b"hello");
        wire.extend(encode(b""));
        wire.extend(encode(b"world!"));
        d.extend(&wire[..3]);
        assert!(d.next_frame(100).unwrap().is_none());
        d.extend(&wire[3..]);
        assert_eq!(d.next_frame(100).unwrap().unwrap(), b"hello");
        assert_eq!(d.next_frame(100).unwrap().unwrap(), b"");
        assert_eq!(d.next_frame(100).unwrap().unwrap(), b"world!");
        assert!(d.next_frame(100).unwrap().is_none());
        d.extend(&encode(&[0u8; 200]));
        assert!(matches!(d.next_frame(100), Err(FrameError::TooBig(200, 100))));
    }
}
