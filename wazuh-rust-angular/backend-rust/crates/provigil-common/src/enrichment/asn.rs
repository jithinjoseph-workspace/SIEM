// NDR Engine — ASN Enrichment (MaxMind GeoLite2-ASN)
// Uses maxminddb crate (Apache-2.0). License: Apache-2.0

use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsnInfo {
    pub asn:  u32,
    pub org:  String,
    pub full: String, // e.g. "AS15169 Google LLC"
}

pub struct AsnLookup {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl AsnLookup {
    pub fn open(db_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let reader = maxminddb::Reader::open_readfile(db_path)?;
        Ok(Self { reader })
    }

    pub fn lookup(&self, ip: &str) -> Option<AsnInfo> {
        let addr = IpAddr::from_str(ip).ok()?;
        let record: geoip2::Asn = self.reader.lookup(addr).ok()?;

        let asn = record.autonomous_system_number.unwrap_or(0);
        let org = record.autonomous_system_organization.unwrap_or("").to_string();
        let full = format!("AS{} {}", asn, org);

        Some(AsnInfo { asn, org, full })
    }
}
