//! `read_journald.c` is Linux only (`#ifdef __linux__`): elsewhere there is
//! no journal reader and the file status has no journald entry.

use siem_cjson::Json;

use crate::*;

/// The journal reader state (none here).
#[derive(Default)]
pub struct Journald;

pub fn can_read(_lc: &Lc, _owner_id: u64) -> bool {
    false
}

pub fn read_journald(_lc: &Lc, _lf: &mut Reader, _rc: &mut i32) {}

pub fn set_ofe(_lc: &Lc, _ofe: bool) {}

pub fn get_status_as_json(_lc: &Lc) -> Option<Json> {
    None
}

pub fn set_status_from_json(_lc: &Lc, _global: &Json) {}
