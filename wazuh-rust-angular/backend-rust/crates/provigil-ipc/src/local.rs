//! Sockets at manager paths (relative to the home folder). On Unix a Unix stream socket at the
//! path; on Windows a loopback TCP port, its number written to `<path>.port`.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub type Stream = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
pub type Stream = std::net::TcpStream;

#[cfg(unix)]
pub type Listener = std::os::unix::net::UnixListener;
#[cfg(not(unix))]
pub type Listener = std::net::TcpListener;

/// The file a Windows listener writes its port to.
pub fn port_file(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".port");
    s.into()
}

/// Connects to the socket at `path`.
pub fn connect(path: &Path) -> io::Result<Stream> {
    #[cfg(unix)]
    {
        Stream::connect(path)
    }
    #[cfg(not(unix))]
    {
        let text = std::fs::read_to_string(port_file(path))?;
        let port: u16 = text.trim().parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", port_file(path).display())))?;
        Stream::connect(("127.0.0.1", port))
    }
}

/// Listens at `path` (its folder is created; a stale socket file is replaced).
/// shortcut: on Windows any local user can reach the port; keep the manager on a host of its own,
/// or move to named pipes with an ACL before sharing the machine.
pub fn bind(path: &Path) -> io::Result<Listener> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(path);
        Listener::bind(path)
    }
    #[cfg(not(unix))]
    {
        let l = Listener::bind("127.0.0.1:0")?;
        std::fs::write(port_file(path), l.local_addr()?.port().to_string())?;
        Ok(l)
    }
}

/// Removes what [`bind`] left (the socket file or the port file).
pub fn unbind(path: &Path) {
    #[cfg(unix)]
    let _ = std::fs::remove_file(path);
    #[cfg(not(unix))]
    let _ = std::fs::remove_file(port_file(path));
}

/// Clones a stream (for a reader and a writer on two threads).
pub fn try_clone(s: &Stream) -> io::Result<Stream> {
    s.try_clone()
}
