//! Port of upstream 4.14.7 syscollector module (`wazuh_modules/syscollector/`
//! and `wm_syscollector.c`) on `siem-dbsync` (dbsync + rsync) and
//! `siem-sysinfo` (the data provider).

pub mod normalizer;
pub mod syscollector;
pub mod tables_def;
pub mod wm;
