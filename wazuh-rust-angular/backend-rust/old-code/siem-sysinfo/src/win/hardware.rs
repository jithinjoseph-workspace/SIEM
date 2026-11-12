//! `SysInfo::getHardware()` (sysInfoWin.cpp).

use windows_sys::Win32::System::SystemInformation::*;

use super::registry::*;
use super::{helpers, os, Error};
use crate::json::{f, i, s, u, Obj, Value};
use crate::{strings, UNKNOWN_VALUE};

const CENTRAL_PROCESSOR_REGISTRY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
/// 'RSMB'
const RSMB: u32 = 0x52534D42;

/// `getSerialNumber()`
fn get_serial_number() -> String {
    if os::is_vista_or_greater() {
        // SAFETY: the first call sizes the buffer of the second.
        unsafe {
            let size = GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0);
            if size != 0 {
                let mut buf = vec![0u8; size as usize];
                if GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr().cast(), size) == size && buf.len() >= 8 {
                    // RawSMBIOSData: 4 bytes, DWORD Length, then the table
                    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
                    let end = (8 + len).min(buf.len());
                    return helpers::serial_number_from_smbios(&buf[8..end]);
                }
            }
        }
        String::new()
    } else {
        let raw = super::cmd::exec("wmic baseboard get SerialNumber");
        match raw.find("\r\n") {
            Some(p) => strings::trim(&raw[p..], " \t\r\n").to_string(),
            None => UNKNOWN_VALUE.into(),
        }
    }
}

/// `getCpuName()`: the raw value (the throwing `string()` does not convert).
fn get_cpu_name() -> Result<Vec<u8>, Error> {
    Ok(Registry::read(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY)?.string_raw("ProcessorNameString")?)
}

/// `getCpuMHz()`
fn get_cpu_mhz() -> Result<i32, Error> {
    Ok(Registry::read(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY)?.dword("~MHz")? as i32)
}

/// `getCpuCores()`
fn get_cpu_cores() -> i32 {
    // SAFETY: plain call.
    unsafe {
        let mut si: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut si);
        si.dwNumberOfProcessors as i32
    }
}

/// `SysInfo::getHardware()`
pub fn get_hardware() -> Result<Value, Error> {
    let mut o = Obj::new();
    o.set("board_serial", s(get_serial_number()));
    o.set("cpu_name", s(get_cpu_name()?));
    o.set("cpu_cores", i(get_cpu_cores() as i64));
    o.set("cpu_mhz", f(get_cpu_mhz()? as f64));
    // getMemory
    // SAFETY: plain struct and call.
    unsafe {
        let mut st: MEMORYSTATUSEX = std::mem::zeroed();
        st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut st) == 0 {
            return Err(Error("Error calling GlobalMemoryStatusEx".into()));
        }
        o.set("ram_total", u(st.ullTotalPhys / 1024));
        o.set("ram_free", u(st.ullAvailPhys / 1024));
        o.set("ram_usage", u(st.dwMemoryLoad as u64));
    }
    Ok(o.into_value())
}
