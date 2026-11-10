//! The Windows provider (`sysInfoWin.cpp`).

pub mod accounts;
pub mod browser;
pub mod cmd;
pub mod enc;
pub mod fsx;
pub mod hardware;
pub mod helpers;
pub mod hotfixes;
pub mod network;
pub mod os;
pub mod packages;
pub mod ports;
pub mod processes;
pub mod registry;
pub mod services;

use crate::json::Value;

/// A C++ exception escaping a provider (`what()`).
#[derive(Debug, Clone)]
pub struct Error(pub String);

impl From<registry::RegError> for Error {
    fn from(e: registry::RegError) -> Self {
        Error(e.0)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `SysInfo`
#[derive(Default, Clone, Copy)]
pub struct SysInfo;

impl SysInfo {
    pub fn hardware(&self) -> Result<Value, Error> {
        hardware::get_hardware()
    }

    pub fn os(&self) -> Result<Value, Error> {
        os::get_os_info()
    }

    /// `processes()`: the list (null when empty, like a default nlohmann json).
    pub fn processes(&self) -> Result<Value, Error> {
        let mut v = Vec::new();
        processes::get_processes_info(|p| {
            v.push(p);
            Ok(())
        })?;
        Ok(if v.is_empty() { Value::Null } else { Value::Array(v) })
    }

    /// `processes(callback)`
    pub fn processes_cb(&self, cb: impl FnMut(Value) -> Result<(), Error>) -> Result<(), Error> {
        processes::get_processes_info(cb)
    }

    pub fn hotfixes(&self) -> Result<Value, Error> {
        Ok(hotfixes::get_hotfixes())
    }

    pub fn networks(&self) -> Result<Value, Error> {
        network::get_networks()
    }

    pub fn ports(&self) -> Result<Value, Error> {
        ports::get_ports()
    }

    pub fn services(&self) -> Result<Value, Error> {
        Ok(services::get_services())
    }

    pub fn groups(&self) -> Result<Value, Error> {
        Ok(accounts::get_groups())
    }

    pub fn users(&self) -> Result<Value, Error> {
        accounts::get_users()
    }

    /// `packages()`: the list (null when empty).
    pub fn packages(&self) -> Result<Value, Error> {
        let mut v = Vec::new();
        packages::get_packages(&mut |p| {
            v.push(p);
            Ok(())
        })?;
        Ok(if v.is_empty() { Value::Null } else { Value::Array(v) })
    }

    pub fn browser_extensions(&self) -> Result<Value, Error> {
        Ok(browser::get_browser_extensions())
    }

    /// `packages(callback)`
    pub fn packages_cb(&self, cb: packages::Cb<'_>) -> Result<(), Error> {
        packages::get_packages(cb)
    }
}
