// NDR Engine — GeoIP Enrichment (MaxMind GeoLite2-City)
// Uses maxminddb crate (Apache-2.0). DB downloaded from MaxMind separately.
// License: Apache-2.0

use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
    pub city:         Option<String>,
    pub latitude:     Option<f64>,
    pub longitude:    Option<f64>,
}

pub struct GeoIpLookup {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpLookup {
    pub fn open(db_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let reader = maxminddb::Reader::open_readfile(db_path)?;
        Ok(Self { reader })
    }

    /// Look up GeoIP data for an IP address.
    /// Returns None for private IPs, unknown IPs, or if the DB is unavailable.
    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        let addr = IpAddr::from_str(ip).ok()?;
        let record: geoip2::City = self.reader.lookup(addr).ok()?;

        let country_code = record.country
            .as_ref()
            .and_then(|c| c.iso_code)
            .unwrap_or("")
            .to_string();

        let country_name = record.country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let city = record.city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());

        let latitude  = record.location.as_ref().and_then(|l| l.latitude);
        let longitude = record.location.as_ref().and_then(|l| l.longitude);

        Some(GeoInfo { country_code, country_name, city, latitude, longitude })
    }
}
