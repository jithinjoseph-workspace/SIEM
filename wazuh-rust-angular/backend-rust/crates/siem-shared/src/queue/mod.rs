//! Wazuh Event & Message Queues (file-queue.c, json-queue.c, mq_op.c)
//!
//! Provides disk-backed rotating event queues and bounded memory queues for daemon IPC.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A bounded in-memory message queue for thread-safe daemon IPC.
#[derive(Debug, Clone)]
pub struct MemoryQueue<T> {
    inner: Arc<Mutex<VecDeque<T>>>,
    max_capacity: usize,
}

impl<T> MemoryQueue<T> {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            max_capacity,
        }
    }

    /// Push an element. Returns false if queue is full.
    pub fn push(&self, item: T) -> bool {
        let mut q = self.inner.lock().unwrap();
        if q.len() >= self.max_capacity {
            return false;
        }
        q.push_back(item);
        true
    }

    /// Pop next element from queue.
    pub fn pop(&self) -> Option<T> {
        let mut q = self.inner.lock().unwrap();
        q.pop_front()
    }

    pub fn len(&self) -> usize {
        let q = self.inner.lock().unwrap();
        q.len()
    }

    pub fn is_empty(&self) -> bool {
        let q = self.inner.lock().unwrap();
        q.is_empty()
    }
}

/// A disk-backed rotating file queue.
pub struct DiskQueue {
    base_dir: PathBuf,
    prefix: String,
    max_file_size_bytes: u64,
    current_file_index: u32,
    current_writer: Mutex<Option<File>>,
    current_size: Mutex<u64>,
}

impl DiskQueue {
    pub fn open<P: AsRef<Path>>(
        base_dir: P,
        prefix: &str,
        max_file_size_bytes: u64,
    ) -> Result<Self, std::io::Error> {
        let dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let queue = Self {
            base_dir: dir,
            prefix: prefix.to_string(),
            max_file_size_bytes,
            current_file_index: 0,
            current_writer: Mutex::new(None),
            current_size: Mutex::new(0),
        };

        queue.rotate_if_needed(0)?;
        Ok(queue)
    }

    fn current_path(&self, index: u32) -> PathBuf {
        self.base_dir.join(format!("{}.{}", self.prefix, index))
    }

    fn rotate_if_needed(&self, additional_bytes: u64) -> Result<(), std::io::Error> {
        let mut current_size = self.current_size.lock().unwrap();
        let mut writer_opt = self.current_writer.lock().unwrap();

        if writer_opt.is_none() || (*current_size + additional_bytes > self.max_file_size_bytes) {
            let mut index = self.current_file_index;
            if writer_opt.is_some() {
                index += 1;
            }

            let path = self.current_path(index);
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;

            let size = file.metadata()?.len();
            *writer_opt = Some(file);
            *current_size = size;
        }
        Ok(())
    }

    /// Enqueue a message string as a new line.
    pub fn push_line(&self, line: &str) -> Result<(), std::io::Error> {
        let bytes = line.as_bytes();
        let total_bytes = bytes.len() as u64 + 1; // including '\n'

        self.rotate_if_needed(total_bytes)?;

        let mut writer_guard = self.current_writer.lock().unwrap();
        let mut size_guard = self.current_size.lock().unwrap();

        if let Some(ref mut file) = *writer_guard {
            file.write_all(bytes)?;
            file.write_all(b"\n")?;
            file.flush()?;
            *size_guard += total_bytes;
        }

        Ok(())
    }

    /// Read all lines from an indexed queue file.
    pub fn read_index_lines(&self, index: u32) -> Result<Vec<String>, std::io::Error> {
        let path = self.current_path(index);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines() {
            lines.push(line?);
        }
        Ok(lines)
    }
}
