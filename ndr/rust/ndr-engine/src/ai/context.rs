//! Plain-text facts about the hosts in an alert, given to the AI session analysis.
//!
//! The analysis used to receive two bare IPs and a severity. It could not say who the other side
//! was, so an ISP's DNS server (port 53, "sensitive" country on the default list) was written up
//! as possible malicious activity. These helpers say who and what, from data the engine already
//! holds (country and provider databases, names seen in DNS traffic).

use crate::enrichment::{AsnInfo, GeoInfo};

/// Well-known service for a destination port, for the prompt ("53/udp (DNS)").
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 | 465 | 587 => "SMTP mail",
        53 => "DNS", 67 | 68 => "DHCP", 80 => "HTTP", 110 | 995 => "POP3 mail",
        123 => "NTP time", 143 | 993 => "IMAP mail", 389 | 636 => "LDAP", 443 => "HTTPS",
        445 => "SMB file sharing", 853 => "DNS over TLS", 1900 => "UPnP", 3389 => "RDP",
        5353 => "mDNS", _ => return None,
    })
}

/// "Destination port: 53/udp (DNS)". Empty when the port is unknown.
pub fn connection_line(dst_port: Option<u16>, proto: Option<&str>) -> String {
    let Some(port) = dst_port.filter(|p| *p > 0) else { return String::new() };
    let proto = proto.filter(|p| !p.is_empty()).map(|p| format!("/{}", p.to_lowercase())).unwrap_or_default();
    match service_name(port) {
        Some(name) => format!("Destination port: {port}{proto} ({name})\n"),
        None       => format!("Destination port: {port}{proto}\n"),
    }
}

/// One line about an address: whether it is internal, and for a public one the country, the
/// network operator and any names it was seen under. `label` is "SOURCE" or "DESTINATION".
pub fn ip_facts(label: &str, ip: &str, is_private: bool, geo: Option<&GeoInfo>,
                asn: Option<&AsnInfo>, names: &[String]) -> String {
    if ip.is_empty() { return String::new(); }
    if is_private {
        return format!("{label} {ip}: internal (private) address\n");
    }
    let mut parts = vec!["public address".to_string()];
    if let Some(g) = geo.filter(|g| !g.country_code.is_empty()) {
        let name = if g.country_name.is_empty() { g.country_code.clone() } else { g.country_name.clone() };
        parts.push(format!("country {} ({})", name, g.country_code));
    }
    if let Some(a) = asn {
        parts.push(format!("network operator AS{} {}", a.asn, a.org));
    }
    if !names.is_empty() {
        parts.push(format!("seen in DNS traffic as {}", names.join(", ")));
    }
    if parts.len() == 1 {
        parts.push("no country, operator or name information available".to_string());
    }
    format!("{label} {ip}: {}\n", parts.join("; "))
}

/// Threat-intel history of the source host as FACTS. It used to be "confirmed C2 ... treat this host
/// as compromised" for a single match of any kind, which made every later alert from that host read
/// as an attack, whatever the evidence.
pub fn host_history_text(host: &str, matches: u64, peers: &[String]) -> String {
    if matches == 0 { return String::new(); }
    let who = if peers.is_empty() { String::new() } else { format!(" (involving {})", peers.join(", ")) };
    format!(
        "HOST THREAT-INTEL MATCHES: {host} appeared in {matches} alert(s) that matched a threat-intelligence \
         feed in the last 24 hours{who}. A feed match is a lead, not proof of compromise: weigh it \
         against the evidence of this session.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo(code: &str, name: &str) -> GeoInfo {
        GeoInfo { country_code: code.into(), country_name: name.into(), city: None, latitude: None, longitude: None }
    }
    fn asn(n: u32, org: &str) -> AsnInfo { AsnInfo { asn: n, org: org.into(), full: format!("AS{n} {org}") } }

    #[test]
    fn a_dns_server_is_described_as_such() {
        assert_eq!(connection_line(Some(53), Some("UDP")), "Destination port: 53/udp (DNS)\n");
        assert_eq!(connection_line(Some(49152), Some("tcp")), "Destination port: 49152/tcp\n");
        assert_eq!(connection_line(Some(53), None), "Destination port: 53 (DNS)\n");
        assert_eq!(connection_line(None, Some("tcp")), "");
        assert_eq!(connection_line(Some(0), Some("tcp")), "");
    }

    #[test]
    fn a_public_address_says_country_operator_and_name() {
        let l = ip_facts("DESTINATION", "103.160.195.230", false, Some(&geo("IN", "India")),
                         Some(&asn(64512, "Example ISP Ltd")), &["dns.example-isp.com".to_string()]);
        assert_eq!(l, "DESTINATION 103.160.195.230: public address; country India (IN); \
                       network operator AS64512 Example ISP Ltd; seen in DNS traffic as dns.example-isp.com\n");
    }

    #[test]
    fn missing_data_is_said_plainly_not_invented() {
        let l = ip_facts("DESTINATION", "203.0.113.9", false, None, None, &[]);
        assert!(l.contains("no country, operator or name information available"), "{l}");
        assert_eq!(ip_facts("SOURCE", "10.0.2.15", true, None, None, &[]), "SOURCE 10.0.2.15: internal (private) address\n");
        assert_eq!(ip_facts("SOURCE", "", false, None, None, &[]), "");
    }

    #[test]
    fn threat_intel_history_is_stated_as_a_lead_not_a_verdict() {
        assert_eq!(host_history_text("10.0.2.15", 0, &[]), "");
        let t = host_history_text("10.0.2.15", 3, &["1.2.3.4".to_string()]);
        assert!(t.contains("3 alert(s)") && t.contains("1.2.3.4"), "{t}");
        assert!(!t.to_lowercase().contains("treat this host as compromised"), "{t}");
        assert!(t.contains("not proof"), "{t}");
    }

    // With the real GeoLite2 files shipped in data/ (run from the crate directory):
    //   cargo test -p ndr-engine real_databases -- --ignored --nocapture
    #[test]
    #[ignore]
    fn real_databases_describe_an_isp_dns_server() {
        use crate::enrichment::{AsnLookup, GeoIpLookup};
        let geo = GeoIpLookup::open("data/GeoLite2-City.mmdb").expect("City database");
        let asn = AsnLookup::open("data/GeoLite2-ASN.mmdb").expect("ASN database");
        let ip = "103.160.195.230"; // dns.keralavisionisp.com
        let (g, a) = (geo.lookup(ip), asn.lookup(ip));
        let line = ip_facts("DESTINATION", ip, false, g.as_ref(), a.as_ref(), &[]);
        println!("{line}{}", connection_line(Some(53), Some("udp")));
        assert!(g.is_some_and(|g| g.country_code == "IN"), "country from the City database");
        assert!(a.is_some_and(|a| !a.org.is_empty()), "operator from the ASN database");
    }
}
