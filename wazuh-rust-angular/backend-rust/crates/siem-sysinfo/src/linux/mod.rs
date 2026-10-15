//! The Linux provider (`sysInfoLinux.cpp`).

pub mod accounts;
pub mod hardware;
pub mod network;
pub mod os;
pub mod packages;
pub mod ports;
pub mod processes;
pub mod services;

use crate::json::Value;

/// An error escaping a provider (`what()`).
#[derive(Debug, Clone)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `SysInfo` Linux implementation matching `win::SysInfo`
#[derive(Default, Clone, Copy)]
pub struct SysInfo;

impl SysInfo {
    pub fn new() -> Self {
        Self
    }

    pub fn hardware(&self) -> Result<Value, Error> {
        hardware::get_hardware()
    }

    pub fn os(&self) -> Result<Value, Error> {
        os::get_os_info()
    }

    pub fn processes(&self) -> Result<Value, Error> {
        let mut v = Vec::new();
        processes::get_processes_info(|p| {
            v.push(p);
            Ok(())
        })?;
        Ok(if v.is_empty() { Value::Null } else { Value::Array(v) })
    }

    pub fn processes_cb(&self, cb: impl FnMut(Value) -> Result<(), Error>) -> Result<(), Error> {
        processes::get_processes_info(cb)
    }

    pub fn hotfixes(&self) -> Result<Value, Error> {
        Ok(Value::Null)
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
        accounts::get_groups()
    }

    pub fn users(&self) -> Result<Value, Error> {
        accounts::get_users()
    }

    pub fn packages(&self) -> Result<Value, Error> {
        packages::get_packages()
    }
}
