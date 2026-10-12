//! Port of Wazuh 4.14.7's `data_provider` (`src/data_provider/`): the
//! `SysInfo` class syscollector reads its inventory from.
//!
//! Every category is an nlohmann JSON value ([`siem_njson::Value`], whose
//! `dump()` matches nlohmann byte for byte: syscollector checksums it).
//! Number types follow the C++ assignments: unsigned for `DWORD` /
//! `ULONGLONG`, signed for `int` / `LONG`, float for `double`.
//!
//! The Windows provider (`sysInfoWin.cpp` and its helpers) behaves like the
//! 32-bit `sysinfo.dll` the Windows agent ships: registry keys the C opens
//! without a `KEY_WOW64_*` flag are read through the 32-bit view.

pub mod json;
pub mod strings;

#[cfg(windows)]
pub mod win;

#[cfg(windows)]
pub use win::SysInfo;

/// `UNKNOWN_VALUE` (sharedDefs.h)
pub const UNKNOWN_VALUE: &str = " ";
