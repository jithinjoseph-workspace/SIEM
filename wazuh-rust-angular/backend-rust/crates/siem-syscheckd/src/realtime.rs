use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealtimeEvent {
    Create(PathBuf),
    Modify(PathBuf),
    Delete(PathBuf),
}

pub struct RealtimeWatcher {
    tx: mpsc::Sender<RealtimeEvent>,
    monitored_paths: Vec<PathBuf>,
}

impl RealtimeWatcher {
    pub fn new(tx: mpsc::Sender<RealtimeEvent>) -> Self {
        Self {
            tx,
            monitored_paths: Vec::new(),
        }
    }

    pub fn add_path(&mut self, path: impl Into<PathBuf>) {
        let p = path.into();
        info!("Registered realtime watch on {}", p.display());
        self.monitored_paths.push(p);
    }

    /// Emits a simulated or detected real-time filesystem event
    pub async fn emit_event(&self, event: RealtimeEvent) -> Result<(), mpsc::error::SendError<RealtimeEvent>> {
        self.tx.send(event).await
    }

    pub fn monitored_count(&self) -> usize {
        self.monitored_paths.len()
    }

    /// Spawns the Linux inotify event loop (mirroring Wazuh run_realtime.c)
    #[cfg(target_os = "linux")]
    pub fn start_inotify_listener(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            use std::collections::HashMap;
            use std::fs::File;
            use std::os::unix::io::FromRawFd;

            let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if inotify_fd < 0 {
                tracing::warn!("siem-syscheckd: inotify_init1 failed. Fallback to polling mode.");
                return;
            }

            let mut wd_to_path: HashMap<i32, PathBuf> = HashMap::new();
            let mask = libc::IN_MODIFY
                | libc::IN_ATTRIB
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF;

            for p in &self.monitored_paths {
                if let Ok(c_path) = std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
                    let wd = unsafe { libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask) };
                    if wd >= 0 {
                        wd_to_path.insert(wd, p.clone());
                    }
                }
            }

            let file = unsafe { File::from_raw_fd(inotify_fd) };
            let async_fd = match tokio::io::unix::AsyncFd::new(file) {
                Ok(afd) => afd,
                Err(e) => {
                    tracing::error!("siem-syscheckd: Failed to create AsyncFd: {}", e);
                    return;
                }
            };

            let mut raw_buf = [0u8; 8192];
            loop {
                match async_fd.readable().await {
                    Ok(mut guard) => {
                        let res = guard.try_io(|inner| {
                            use std::io::Read;
                            (&*inner.get_ref()).read(&mut raw_buf)
                        });

                        match res {
                            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                                let mut offset = 0;
                                while offset + std::mem::size_of::<libc::inotify_event>() <= bytes_read {
                                    let event_ptr = raw_buf[offset..].as_ptr() as *const libc::inotify_event;
                                    let event = unsafe { &*event_ptr };
                                    let name_len = event.len as usize;

                                    let event_name = if name_len > 0 {
                                        let name_bytes = &raw_buf[offset + std::mem::size_of::<libc::inotify_event>()..offset + std::mem::size_of::<libc::inotify_event>() + name_len];
                                        let trimmed = name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes);
                                        String::from_utf8_lossy(trimmed).to_string()
                                    } else {
                                        String::new()
                                    };

                                    if let Some(dir_path) = wd_to_path.get(&event.wd) {
                                        let full_path = if event_name.is_empty() {
                                            dir_path.clone()
                                        } else {
                                            dir_path.join(&event_name)
                                        };

                                        let rt_event = if (event.mask & (libc::IN_DELETE | libc::IN_DELETE_SELF | libc::IN_MOVED_FROM)) != 0 {
                                            RealtimeEvent::Delete(full_path)
                                        } else if (event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0 {
                                            RealtimeEvent::Create(full_path)
                                        } else {
                                            RealtimeEvent::Modify(full_path)
                                        };

                                        let _ = self.tx.send(rt_event).await;
                                    }

                                    offset += std::mem::size_of::<libc::inotify_event>() + name_len;
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    }
}
