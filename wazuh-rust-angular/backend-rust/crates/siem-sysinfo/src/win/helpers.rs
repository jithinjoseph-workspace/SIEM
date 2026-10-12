//! `windowsHelper.h` and the `timeHelper.h` parts the Windows provider
//! uses, with the C runtime's time functions.

use crate::strings;

/// `WINDOWS_UNIX_EPOCH_DIFF_SECONDS`
pub const WINDOWS_UNIX_EPOCH_DIFF_SECONDS: u64 = 11644473600;

/// `struct tm` of the C runtime.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

extern "C" {
    fn _mktime64(tm: *mut Tm) -> i64;
    fn _localtime64_s(tm: *mut Tm, t: *const i64) -> i32;
    fn _gmtime64_s(tm: *mut Tm, t: *const i64) -> i32;
}

/// `mktime`
pub fn mktime(tm: &mut Tm) -> i64 {
    // SAFETY: a valid tm.
    unsafe { _mktime64(tm) }
}

/// `gmtime_r` / `localtime_r`
pub fn tm_of(t: i64, utc: bool) -> Option<Tm> {
    let mut tm = Tm::default();
    // SAFETY: valid pointers.
    let r = unsafe {
        if utc {
            _gmtime64_s(&mut tm, &t)
        } else {
            _localtime64_s(&mut tm, &t)
        }
    };
    (r == 0).then_some(tm)
}

/// `Utils::getTimestamp(time, utc)`: "YYYY/MM/DD hh:mm:ss"
pub fn get_timestamp(t: i64, utc: bool) -> String {
    match tm_of(t, utc) {
        None => "1970/01/01 00:00:00".into(),
        Some(tm) => format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        ),
    }
}

/// `Utils::getCurrentTimestamp()`
pub fn current_timestamp() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    get_timestamp(now, true)
}

/// `Utils::buildTimestamp(FILETIME)`: strftime "%Y/%m/%d %H:%M:%S" in UTC
/// of the 18-digit LDAP/FILETIME value (`static_cast<long>`: 32 bits on
/// Windows).
pub fn build_timestamp(time: u64) -> String {
    let epoch = ((time / 10_000_000).wrapping_sub(WINDOWS_UNIX_EPOCH_DIFF_SECONDS)) as i32 as i64;
    match tm_of(epoch, true) {
        Some(tm) => format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        ),
        // gmtime_s failed: strftime of a zeroed tm
        None => "1900/01/00 00:00:00".into(),
    }
}

/// `Utils::normalizeTimestamp(InstallDate "YYYYMMDD", "YYYY/MM/DD hh:mm:ss")`
pub fn normalize_timestamp(calendar: &str, combined: &str) -> Result<String, String> {
    if calendar.len() != 8 {
        return Err("Invalid dateISO8601CalendarDateFormat size.".into());
    }
    if !strings::is_number(calendar) {
        return Err("Invalid dateISO8601CalendarDateFormat format.".into());
    }
    let Some(pos) = combined.find(' ') else {
        return Err("Invalid dateISO8601CombinedFormat date/time separator.".into());
    };
    let mut date = combined[..pos].to_string();
    let mut time = combined[pos + 1..].to_string();
    strings::replace_all(&mut date, "/", "");
    strings::replace_all(&mut time, ":", "");
    if date.len() == 8 || time.len() == 6 {
        if date == calendar {
            Ok(combined.to_string())
        } else {
            let stoi = |s: &str| strings::stoi(s).map(|v| v.0).map_err(|_| "stoi".to_string());
            let mut tm = Tm {
                tm_year: stoi(&calendar[0..4])? - 1900,
                tm_mon: stoi(&calendar[4..6])? - 1,
                tm_mday: stoi(&calendar[6..8])?,
                ..Default::default()
            };
            let t = mktime(&mut tm);
            Ok(get_timestamp(t, false))
        }
    } else {
        Err("Invalid dateISO8601CombinedFormat format.".into())
    }
}

/// `Utils::getSerialNumberFromSmbios`
pub fn serial_number_from_smbios(raw: &[u8]) -> String {
    let size = raw.len();
    let mut tmp = raw.to_vec();
    tmp.push(0);
    let cstr = |off: usize| -> &[u8] {
        let end = tmp[off..].iter().position(|&c| c == 0).map(|p| off + p).unwrap_or(tmp.len());
        &tmp[off..end]
    };
    let mut serial: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    while offset < size && serial.is_empty() {
        // sizeof(SMBIOSStructureHeader) = 4
        if offset + 4 >= size {
            break;
        }
        let ty = tmp[offset];
        let flen = tmp[offset + 1] as usize;
        // sizeof(SMBIOSBaseboardInfoStructure) = 8
        if offset + flen >= size || offset + 8 >= size {
            break;
        }
        if ty == 2 {
            let serial_idx = tmp[offset + 7];
            offset += flen;
            let mut i: u8 = 1;
            while i < serial_idx {
                if offset < size {
                    offset += cstr(offset).len() + 1;
                }
                i = i.wrapping_add(1);
            }
            if offset < size {
                serial = cstr(offset).to_vec();
            }
        } else {
            offset += flen;
            while offset + 1 < size {
                if tmp[offset] == 0 && tmp[offset + 1] == 0 {
                    offset += 2;
                    break;
                }
                offset += 1;
            }
        }
    }
    String::from_utf8_lossy(&serial).into_owned()
}

/// `NetworkWindowsHelper::ipv6Netmask`
pub fn ipv6_netmask(mask_length: u8) -> String {
    let mut netmask = String::new();
    if mask_length < 128 {
        netmask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into();
        let value = mask_length as i32 / 4;
        let remaining = mask_length as i32 % 4;
        let total = value + remaining;
        let refill = total % 4;
        let separators = value / 4;
        let rem_sep = value % 4;
        let final_sep = if rem_sep == 0 { separators - 1 } else { separators };
        // substr(0, n): a negative n converts to npos (the whole string)
        let n = value + final_sep;
        if n >= 0 {
            netmask.truncate((n as usize).min(netmask.len()));
        }
        if remaining != 0 {
            match remaining {
                1 => netmask.push('8'),
                2 => netmask.push('c'),
                3 => netmask.push('e'),
                _ => {}
            }
        } else {
            netmask.push_str(&"0".repeat(refill as usize));
        }
        if total < 32 - 4 {
            netmask.push_str("::");
        }
    }
    netmask
}
