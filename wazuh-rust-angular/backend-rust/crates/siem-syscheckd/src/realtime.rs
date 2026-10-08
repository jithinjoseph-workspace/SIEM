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
}
