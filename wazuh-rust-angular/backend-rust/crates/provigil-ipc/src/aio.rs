//! Async local sockets at manager paths (tokio). Unix: Unix sockets (permissions 0660). Windows: a
//! loopback port whose number the listener writes to `<path>.port`.
//!
//! * [`DatagramReceiver`] / [`DatagramSender`]: one message per datagram (the detection engine's
//!   event queue, the active-response queue).
//! * [`StreamListener`] / [`LocalStream`]: request/answer connections, with [`framing`].

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::local::port_file;

#[cfg(not(unix))]
fn read_port(path: &Path) -> io::Result<u16> {
    let s = std::fs::read_to_string(port_file(path))?;
    s.trim().parse::<u16>().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", port_file(path).display())))
}

#[cfg(not(unix))]
fn write_port(path: &Path, port: u16) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(port_file(path), port.to_string())
}

/// The folder exists and a stale socket file is gone.
fn prepare(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(unix)]
fn group_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
}

// ------------------------------------------------------------------ datagrams

/// A bound datagram socket that receives messages.
pub struct DatagramReceiver {
    #[cfg(unix)]
    sock: tokio::net::UnixDatagram,
    #[cfg(not(unix))]
    sock: tokio::net::UdpSocket,
    path: PathBuf,
}

impl DatagramReceiver {
    pub async fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        prepare(&path)?;
        #[cfg(unix)]
        {
            let sock = tokio::net::UnixDatagram::bind(&path)?;
            group_only(&path);
            Ok(Self { sock, path })
        }
        #[cfg(not(unix))]
        {
            // senders stay connected to the previous run's port (a UDP send to a closed port does
            // not fail), so a restarted receiver takes that port back when it is free
            let sock = match read_port(&path) {
                Ok(p) => match tokio::net::UdpSocket::bind(("127.0.0.1", p)).await {
                    Ok(s) => s,
                    Err(_) => tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
                },
                Err(_) => tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
            };
            write_port(&path, sock.local_addr()?.port())?;
            // the default receive buffer overflows on a burst (a batch of checks from one agent)
            {
                use std::os::windows::io::AsRawSocket;
                use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_RCVBUF};
                let size: i32 = 16 * 1024 * 1024;
                // SAFETY: a live socket and a 4-byte option value
                unsafe { setsockopt(sock.as_raw_socket() as SOCKET, SOL_SOCKET, SO_RCVBUF, (&size as *const i32).cast(), 4) };
            }
            Ok(Self { sock, path })
        }
    }

    /// One message, at most `max` bytes.
    pub async fn recv(&self, max: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        #[cfg(unix)]
        let n = self.sock.recv(&mut buf).await?;
        #[cfg(not(unix))]
        let (n, _) = self.sock.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A datagram socket connected to a receiver.
pub struct DatagramSender {
    #[cfg(unix)]
    sock: tokio::net::UnixDatagram,
    #[cfg(not(unix))]
    sock: tokio::net::UdpSocket,
}

impl DatagramSender {
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            let sock = tokio::net::UnixDatagram::unbound()?;
            sock.connect(path)?;
            Ok(Self { sock })
        }
        #[cfg(not(unix))]
        {
            let port = read_port(path)?;
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            sock.connect(("127.0.0.1", port)).await?;
            Ok(Self { sock })
        }
    }

    pub async fn send(&self, msg: &[u8]) -> io::Result<()> {
        self.sock.send(msg).await.map(|_| ())
    }
}

// ------------------------------------------------------------------ streams

/// A bound stream listener.
pub struct StreamListener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(not(unix))]
    inner: tokio::net::TcpListener,
}

/// A connected local stream.
pub enum LocalStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream),
}

impl StreamListener {
    pub async fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        prepare(path)?;
        #[cfg(unix)]
        {
            let inner = tokio::net::UnixListener::bind(path)?;
            group_only(path);
            Ok(Self { inner })
        }
        #[cfg(not(unix))]
        {
            let inner = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            write_port(path, inner.local_addr()?.port())?;
            Ok(Self { inner })
        }
    }

    pub async fn accept(&self) -> io::Result<LocalStream> {
        let (s, _) = self.inner.accept().await?;
        #[cfg(unix)]
        return Ok(LocalStream::Unix(s));
        #[cfg(not(unix))]
        return Ok(LocalStream::Tcp(s));
    }
}

impl LocalStream {
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        return Ok(LocalStream::Unix(tokio::net::UnixStream::connect(path).await?));
        #[cfg(not(unix))]
        return Ok(LocalStream::Tcp(tokio::net::TcpStream::connect(("127.0.0.1", read_port(path)?)).await?));
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
            LocalStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
            LocalStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_flush(cx),
            LocalStream::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
            LocalStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ------------------------------------------------------------------ framing

/// Messages preceded by their length (u32, little endian), on async streams.
pub mod framing {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[derive(Debug)]
    pub enum FrameError {
        /// The peer closed before a message started.
        Closed,
        /// The announced size (first) is over the limit (second).
        TooBig(usize, usize),
        Io(std::io::Error),
    }

    impl std::fmt::Display for FrameError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FrameError::Closed => write!(f, "connection closed"),
                FrameError::TooBig(n, max) => write!(f, "message of {n} bytes exceeds the limit of {max}"),
                FrameError::Io(e) => write!(f, "{e}"),
            }
        }
    }

    impl std::error::Error for FrameError {}

    impl From<std::io::Error> for FrameError {
        fn from(e: std::io::Error) -> Self {
            FrameError::Io(e)
        }
    }

    /// The message with its length in front.
    pub fn encode(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(payload.len() + 4);
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    pub async fn send<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        w.write_all(&encode(payload)).await?;
        w.flush().await?;
        Ok(())
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A burst sent before the receiver reads (2,000 messages of 1.5 KB) arrives complete.
    #[tokio::test]
    async fn a_burst_is_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path().join("queue/sockets/queue");
        let rx = DatagramReceiver::bind(&q).await.unwrap();
        let tx = DatagramSender::connect(&q).await.unwrap();
        let msg = vec![b'x'; 1500];
        for _ in 0..2000 {
            tx.send(&msg).await.unwrap();
        }
        let mut n = 0;
        while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(500), rx.recv(65536)).await {
            n += 1;
        }
        assert_eq!(n, 2000);
    }

    #[tokio::test]
    async fn datagram_and_stream_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path().join("queue/sockets/queue");
        let rx = DatagramReceiver::bind(&q).await.unwrap();
        let tx = DatagramSender::connect(&q).await.unwrap();
        tx.send(b"1:test:hello").await.unwrap();
        assert_eq!(rx.recv(65536).await.unwrap(), b"1:test:hello");

        let s = dir.path().join("queue/db/wdb");
        let l = StreamListener::bind(&s).await.unwrap();
        let server = tokio::spawn(async move {
            let mut c = l.accept().await.unwrap();
            let q = framing::recv(&mut c, 65536).await.unwrap();
            framing::send(&mut c, &[b"ok ".as_slice(), &q].concat()).await.unwrap();
            assert!(matches!(framing::recv(&mut c, 65536).await, Err(framing::FrameError::Closed)));
        });
        let mut c = LocalStream::connect(&s).await.unwrap();
        framing::send(&mut c, b"ping").await.unwrap();
        assert_eq!(framing::recv(&mut c, 65536).await.unwrap(), b"ok ping");
        drop(c);
        server.await.unwrap();
        let mut big = &framing::encode(&[0u8; 10])[..];
        assert!(matches!(framing::recv(&mut big, 5).await, Err(framing::FrameError::TooBig(10, 5))));
    }

    #[tokio::test]
    async fn sender_reaches_restarted_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path().join("queue/sockets/queue");
        let rx = DatagramReceiver::bind(&q).await.unwrap();
        let tx = DatagramSender::connect(&q).await.unwrap();
        drop(rx);
        let rx = DatagramReceiver::bind(&q).await.unwrap();
        tx.send(b"after restart").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv(65536)).await;
        assert_eq!(got.expect("message lost after the receiver restarted").unwrap(), b"after restart");
    }
}
