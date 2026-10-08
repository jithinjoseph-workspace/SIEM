//! Local sockets at Wazuh paths (`OS_BindUnixDomain`, `OS_ConnectUnixDomain`,
//! `OS_SendUnix`, `OS_RecvUnix`).
//!
//! On Unix these are `AF_UNIX` sockets. On Windows, which has no `AF_UNIX`
//! datagram support in tokio, each path maps to a loopback port that the
//! binder writes to `<path>.port`.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(not(unix))]
fn port_file(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".port");
    PathBuf::from(p)
}

#[cfg(not(unix))]
fn read_port(path: &Path) -> io::Result<u16> {
    let s = std::fs::read_to_string(port_file(path))?;
    s.trim().parse::<u16>().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(not(unix))]
fn write_port(path: &Path, port: u16) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(port_file(path), port.to_string())
}

fn prepare_bind(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    // OS_BindUnixDomain unlinks a stale socket first.
    let _ = std::fs::remove_file(path);
    Ok(())
}

/// A bound datagram socket that receives messages (`StartMQ(path, READ)`).
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
        prepare_bind(&path)?;
        #[cfg(unix)]
        {
            let sock = tokio::net::UnixDatagram::bind(&path)?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
            Ok(Self { sock, path })
        }
        #[cfg(not(unix))]
        {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            write_port(&path, sock.local_addr()?.port())?;
            Ok(Self { sock, path })
        }
    }

    /// `OS_RecvUnix`: one message, at most `max` bytes.
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

/// A connected datagram sender (`StartMQ(path, WRITE)` + `OS_SendUnix`).
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

/// A bound stream listener (`OS_BindUnixDomain(path, SOCK_STREAM, ...)`).
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
        prepare_bind(path)?;
        #[cfg(unix)]
        {
            let inner = tokio::net::UnixListener::bind(path)?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
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
        #[cfg(unix)]
        {
            let (s, _) = self.inner.accept().await?;
            Ok(LocalStream::Unix(s))
        }
        #[cfg(not(unix))]
        {
            let (s, _) = self.inner.accept().await?;
            Ok(LocalStream::Tcp(s))
        }
    }
}

impl LocalStream {
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            Ok(LocalStream::Unix(tokio::net::UnixStream::connect(path).await?))
        }
        #[cfg(not(unix))]
        {
            let port = read_port(path)?;
            Ok(LocalStream::Tcp(tokio::net::TcpStream::connect(("127.0.0.1", port)).await?))
        }
    }
}

impl tokio::io::AsyncRead for LocalStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for LocalStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagram_and_stream_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let qpath = dir.path().join("queue/sockets/queue");
        let rx = DatagramReceiver::bind(&qpath).await.unwrap();
        let tx = DatagramSender::connect(&qpath).await.unwrap();
        tx.send(b"1:test:hello").await.unwrap();
        assert_eq!(rx.recv(65536).await.unwrap(), b"1:test:hello");

        let spath = dir.path().join("queue/db/wdb");
        let l = StreamListener::bind(&spath).await.unwrap();
        let server = tokio::spawn(async move {
            let mut s = l.accept().await.unwrap();
            let q = crate::framing::recv(&mut s, 65536).await.unwrap();
            crate::framing::send(&mut s, &[b"ok ".as_slice(), &q].concat()).await.unwrap();
        });
        let mut c = LocalStream::connect(&spath).await.unwrap();
        crate::framing::send(&mut c, b"ping").await.unwrap();
        assert_eq!(crate::framing::recv(&mut c, 65536).await.unwrap(), b"ok ping");
        server.await.unwrap();
    }
}
