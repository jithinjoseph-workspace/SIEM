// ip_token — HMAC-SHA256 of raw IP using tenant-scoped key
// ALL IP fields in every parsed event are replaced with their token.
// Raw IPs never appear in analytics columns (NFR-S-02 / T-PARSE-03).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex::encode;

type HmacSha256 = Hmac<Sha256>;

/// Returns the HMAC-SHA256 hex token for a given IP and tenant key.
/// The key is derived per-tenant so tokens are not reversible across tenants.
pub fn generate(ip: &str, tenant_key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(tenant_key)
        .expect("HMAC accepts any key size");
    mac.update(ip.as_bytes());
    encode(mac.finalize().into_bytes())
}

/// Walk a JSON value tree and replace every string that looks like an IPv4/IPv6
/// with its HMAC token. Returns the list of tokens generated.
pub fn tokenize_json(value: &mut serde_json::Value, tenant_key: &[u8]) -> Vec<String> {
    let mut tokens = Vec::new();
    tokenize_recursive(value, tenant_key, &mut tokens);
    tokens
}

fn tokenize_recursive(
    value: &mut serde_json::Value,
    tenant_key: &[u8],
    tokens: &mut Vec<String>,
) {
    match value {
        serde_json::Value::String(s) => {
            if is_ip(s) {
                let tok = generate(s, tenant_key);
                tokens.push(tok.clone());
                *s = tok;
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                tokenize_recursive(v, tenant_key, tokens);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                tokenize_recursive(v, tenant_key, tokens);
            }
        }
        _ => {}
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ip_same_key_same_token() {
        let key = b"test-tenant-key";
        let t1 = generate("192.168.1.1", key);
        let t2 = generate("192.168.1.1", key);
        assert_eq!(t1, t2);
    }

    #[test]
    fn different_ips_different_tokens() {
        let key = b"test-tenant-key";
        let t1 = generate("10.0.0.1", key);
        let t2 = generate("10.0.0.2", key);
        assert_ne!(t1, t2);
    }

    #[test]
    fn non_ip_string_not_matched() {
        assert!(!is_ip("hello"));
        assert!(!is_ip("not-an-ip"));
    }

    #[test]
    fn tokenize_json_replaces_ips() {
        let key = b"tenant-key";
        let mut val = serde_json::json!({ "src_ip": "1.2.3.4", "msg": "hello" });
        let tokens = tokenize_json(&mut val, key);
        assert_eq!(tokens.len(), 1);
        assert_ne!(val["src_ip"].as_str().unwrap(), "1.2.3.4");
    }
}
