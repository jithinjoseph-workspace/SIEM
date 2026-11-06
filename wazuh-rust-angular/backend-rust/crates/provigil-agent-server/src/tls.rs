//! The certificate of the agent listeners, from the install-wide CA in `data/tls/`.
//! siem-api creates that CA; a gateway only reads it, and never replaces a key it cannot read.

use std::path::Path;

use chrono::{Datelike, Utc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

pub const CA_CN: &str = "ProVigil Agent CA";

/// The CA's fixed fields: the same name and key give a certificate that chains to the saved one.
pub fn named_ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "Provigil AETHER");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = rcgen::date_time_ymd(2025, 1, 1);
    p.not_after = rcgen::date_time_ymd(2045, 1, 1);
    p
}

/// The CA of `dir`: certificate, key, the saved certificate's PEM.
pub fn read_ca(dir: &Path) -> Result<(Certificate, KeyPair, String), String> {
    let (key_file, cert_file) = (dir.join("ca.key.pem"), dir.join("ca.crt.pem"));
    let pem = std::fs::read_to_string(&key_file).map_err(|e| format!("{}: {e}", key_file.display()))?;
    let key = KeyPair::from_pem(&pem).map_err(|e| format!("{}: {e}", key_file.display()))?;
    let ca = named_ca_params(CA_CN).self_signed(&key).map_err(|e| e.to_string())?;
    let cert = std::fs::read_to_string(&cert_file).map_err(|e| format!("{}: {e}", cert_file.display()))?;
    Ok((ca, key, cert))
}

/// A server certificate for `hosts`, ending on 1 January 3 years on: certificate, key, its end
/// as Unix time.
pub fn server_cert(ca: &Certificate, ca_key: &KeyPair, cn: &str, hosts: Vec<String>) -> Result<(Certificate, KeyPair, i64), String> {
    let mut p = CertificateParams::new(hosts).map_err(|e| e.to_string())?;
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let year = Utc::now().year();
    p.not_before = rcgen::date_time_ymd(year, 1, 1);
    p.not_after = rcgen::date_time_ymd(year + 3, 1, 1);
    let end = chrono::NaiveDate::from_ymd_opt(year + 3, 1, 1).and_then(|d| d.and_hms_opt(0, 0, 0)).map_or(0, |d| d.and_utc().timestamp());
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = p.signed_by(&key, ca, ca_key).map_err(|e| e.to_string())?;
    Ok((cert, key, end))
}

/// The names agents reach this host by (`extra`: `GATEWAY_PUBLIC_HOSTS`), sorted, no repeats.
pub fn hosts(extra: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = ["SIEM_LAN_IP", "MANAGER_IP", "SITE_DOMAIN"].iter().filter_map(|k| std::env::var(k).ok()).flat_map(|v| v.split(',').map(|h| h.trim().to_string()).collect::<Vec<_>>()).collect();
    hosts.extend_from_slice(extra);
    hosts.extend(sysinfo::System::host_name());
    hosts.extend(local_ip_address::list_afinet_netifas().into_iter().flatten().map(|(_, ip)| ip).filter(|ip| ip.is_ipv4()).map(|ip| ip.to_string()));
    hosts.extend(["localhost".to_string(), "127.0.0.1".to_string()]);
    hosts.retain(|h| !h.is_empty() && h.is_ascii());
    hosts.sort();
    hosts.dedup();
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_read_only_and_hosts() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_ca(d.path()).is_err(), "a gateway never makes a CA");
        let key = KeyPair::generate().unwrap();
        let ca = named_ca_params(CA_CN).self_signed(&key).unwrap();
        std::fs::write(d.path().join("ca.key.pem"), key.serialize_pem()).unwrap();
        std::fs::write(d.path().join("ca.crt.pem"), ca.pem()).unwrap();
        let (ca, key, pem) = read_ca(d.path()).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(server_cert(&ca, &key, "t", vec!["localhost".into()]).unwrap().2 > Utc::now().timestamp());
        let h = hosts(&["manager.corp".into()]);
        assert!(h.iter().any(|x| x == "localhost") && h.iter().any(|x| x == "manager.corp"));
        assert!(h.windows(2).all(|w| w[0] < w[1]));
    }
}
