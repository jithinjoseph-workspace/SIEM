use crate::models::UnmatchedFingerprintSummary;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct NovelFingerprintBuffer {
    pub fingerprint: u64,
    pub signature: String,
    pub samples: VecDeque<String>,
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_synthesizing: bool,
}

pub struct SampleAccumulator {
    buffers: RwLock<HashMap<u64, NovelFingerprintBuffer>>,
    max_samples_per_fingerprint: usize,
    default_threshold: usize,
}

impl SampleAccumulator {
    pub fn new(max_samples_per_fingerprint: usize, default_threshold: usize) -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            max_samples_per_fingerprint,
            default_threshold,
        }
    }

    /// Add a sample for an unmatched fingerprint.
    /// Returns `Some(samples)` if the threshold was reached and it is ready for AI synthesis.
    pub fn push_sample(
        &self,
        fingerprint: u64,
        signature: &str,
        raw_log: &str,
    ) -> Option<Vec<String>> {
        let now = Utc::now();
        let mut guard = self.buffers.write().unwrap();
        let entry = guard.entry(fingerprint).or_insert_with(|| NovelFingerprintBuffer {
            fingerprint,
            signature: signature.to_string(),
            samples: VecDeque::with_capacity(self.max_samples_per_fingerprint),
            count: 0,
            first_seen: now,
            last_seen: now,
            is_synthesizing: false,
        });

        entry.count += 1;
        entry.last_seen = now;

        // Deduplicate exact strings in the sample window
        let trimmed = raw_log.trim().to_string();
        if !entry.samples.contains(&trimmed) {
            if entry.samples.len() >= self.max_samples_per_fingerprint {
                entry.samples.pop_front();
            }
            entry.samples.push_back(trimmed);
        }

        if entry.samples.len() >= self.default_threshold && !entry.is_synthesizing {
            entry.is_synthesizing = true;
            Some(entry.samples.iter().cloned().collect())
        } else {
            None
        }
    }

    pub fn get_samples(&self, fingerprint: u64) -> Option<Vec<String>> {
        let guard = self.buffers.read().unwrap();
        guard.get(&fingerprint).map(|b| b.samples.iter().cloned().collect())
    }

    pub fn mark_synthesizing(&self, fingerprint: u64, synthesizing: bool) {
        let mut guard = self.buffers.write().unwrap();
        if let Some(buf) = guard.get_mut(&fingerprint) {
            buf.is_synthesizing = synthesizing;
        }
    }

    pub fn remove(&self, fingerprint: u64) {
        let mut guard = self.buffers.write().unwrap();
        guard.remove(&fingerprint);
    }

    pub fn list_unmatched(&self) -> Vec<UnmatchedFingerprintSummary> {
        let guard = self.buffers.read().unwrap();
        let mut list = Vec::new();

        for buf in guard.values() {
            let previews: Vec<String> = buf.samples.iter().take(3).cloned().collect();
            list.push(UnmatchedFingerprintSummary {
                fingerprint: buf.fingerprint,
                signature: buf.signature.clone(),
                sample_count: buf.samples.len(),
                first_seen: buf.first_seen,
                last_seen: buf.last_seen,
                ready_for_synthesis: buf.samples.len() >= self.default_threshold,
                sample_previews: previews,
            });
        }

        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        list
    }

    pub fn count_pending(&self) -> usize {
        let guard = self.buffers.read().unwrap();
        guard.len()
    }
}
