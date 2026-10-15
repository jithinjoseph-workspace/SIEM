use serde::{Deserialize, Serialize};
use std::net::{IpAddr, UdpSocket};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub id: String,
    pub address: String,
    pub host: String,
    pub port: u16,
    pub label: String,
    pub is_recommended: bool,
    pub is_routable: bool,
    pub adapter_type: String, // "configured", "wifi", "lan", "vm_host_only", "loopback", "custom"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpointsResponse {
    pub recommended_endpoint: String,
    pub configured_public_url: Option<String>,
    pub endpoints: Vec<NetworkEndpoint>,
}

/// Detects the machine's primary outbound IPv4 address by querying the OS routing table.
/// This connects a non-blocking UDP socket to an internet-routable IP (e.g. 8.8.8.8:80).
/// No packets are sent over the wire; the OS kernel simply resolves the egress interface.
fn get_outbound_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Probes a specific destination subnet (e.g. VirtualBox 192.168.56.0/24 or private LAN 10.0.0.0/8)
/// to detect if the host has an adapter bound to that network segment.
fn probe_subnet_ip(dest: &str) -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(dest).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Collects available network interfaces and formats them into candidate agent endpoints.
pub fn discover_network_endpoints(port: u16) -> NetworkEndpointsResponse {
    let mut endpoints: Vec<NetworkEndpoint> = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();

    // 1. Check explicit environment configuration (highest priority for production / reverse proxies)
    let env_public_url = std::env::var("SIEM_PUBLIC_URL")
        .or_else(|_| std::env::var("SIEM_MANAGER_URL"))
        .ok()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty());

    let env_manager_host = std::env::var("SIEM_MANAGER_HOST")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty());

    // 2. Query kernel default route for primary outbound LAN/WAN IP
    let outbound_ip = get_outbound_ip();

    // 3. System adapter inspection on Windows
    #[cfg(windows)]
    {
        if let Ok(sys_val) = siem_sysinfo::SysInfo.networks() {
            if let Ok(dump_bytes) = sys_val.dump() {
                if let Ok(json_obj) = serde_json::from_slice::<serde_json::Value>(&dump_bytes) {
                    if let Some(ifaces) = json_obj.get("iface").and_then(|v| v.as_array()) {
                        for iface in ifaces {
                            let state = iface.get("state").and_then(|s| s.as_str()).unwrap_or("down");
                            if state != "up" {
                                continue;
                            }
                            let name = iface.get("name").and_then(|s| s.as_str()).unwrap_or("Interface");
                            let adapter = iface.get("adapter").and_then(|s| s.as_str()).unwrap_or("");
                            let if_type = iface.get("type").and_then(|s| s.as_str()).unwrap_or("");

                            if let Some(ipv4_list) = iface.get("IPv4").and_then(|v| v.as_array()) {
                                for ip_item in ipv4_list {
                                    if let Some(addr) = ip_item.get("address").and_then(|a| a.as_str()) {
                                        // Skip loopback and APIPA (169.254.x.x link-local auto-config)
                                        if addr.starts_with("127.") || addr.starts_with("169.254.") {
                                            continue;
                                        }
                                        if !seen_ips.insert(addr.to_string()) {
                                            continue;
                                        }

                                        let is_virtual = adapter.contains("VirtualBox")
                                            || adapter.contains("VMware")
                                            || adapter.contains("Hyper-V")
                                            || name.contains("vEthernet");
                                        let is_wifi = if_type == "wireless" || adapter.contains("Wireless") || adapter.contains("Wi-Fi") || name.contains("Wi-Fi");

                                        let adapter_type = if is_virtual {
                                            "vm_host_only".to_string()
                                        } else if is_wifi {
                                            "wifi".to_string()
                                        } else {
                                            "lan".to_string()
                                        };

                                        let label = if is_virtual {
                                            format!("{} (VM Network: {})", name, addr)
                                        } else if is_wifi {
                                            format!("{} - Wi-Fi ({})", name, addr)
                                        } else {
                                            format!("{} - LAN Ethernet ({})", name, addr)
                                        };

                                        let is_outbound = outbound_ip.map(|o| o.to_string() == addr).unwrap_or(false);

                                        endpoints.push(NetworkEndpoint {
                                            id: format!("iface-{}", addr.replace('.', "-")),
                                            address: format!("http://{}:{}", addr, port),
                                            host: addr.to_string(),
                                            port,
                                            label,
                                            is_recommended: is_outbound,
                                            is_routable: true,
                                            adapter_type,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Fallback subnet probes if adapter enumeration didn't pick up specific VM adapters
    if let Some(vb_ip) = probe_subnet_ip("192.168.56.254:80") {
        let addr = vb_ip.to_string();
        if !addr.starts_with("127.") && !addr.starts_with("169.254.") && seen_ips.insert(addr.clone()) {
            endpoints.push(NetworkEndpoint {
                id: format!("vb-{}", addr.replace('.', "-")),
                address: format!("http://{}:{}", addr, port),
                host: addr.clone(),
                port,
                label: format!("VirtualBox Host-Only Adapter ({})", addr),
                is_recommended: false,
                is_routable: true,
                adapter_type: "vm_host_only".to_string(),
            });
        }
    }

    // If outbound IP was discovered but not yet in endpoints list
    if let Some(out_ip) = outbound_ip {
        let addr = out_ip.to_string();
        if !addr.starts_with("127.") && !addr.starts_with("169.254.") && seen_ips.insert(addr.clone()) {
            endpoints.insert(0, NetworkEndpoint {
                id: format!("outbound-{}", addr.replace('.', "-")),
                address: format!("http://{}:{}", addr, port),
                host: addr.clone(),
                port,
                label: format!("Primary Host LAN/WAN ({})", addr),
                is_recommended: true,
                is_routable: true,
                adapter_type: "lan".to_string(),
            });
        }
    }

    // 5. Host environment override if provided
    if let Some(host_override) = env_manager_host {
        let addr = host_override;
        if seen_ips.insert(addr.clone()) {
            endpoints.insert(0, NetworkEndpoint {
                id: "env-manager-host".to_string(),
                address: format!("http://{}:{}", addr, port),
                host: addr.clone(),
                port,
                label: format!("Configured Host ({})", addr),
                is_recommended: true,
                is_routable: true,
                adapter_type: "configured".to_string(),
            });
        }
    }

    // 6. Configured Public URL override (e.g. https://siem.example.com or reverse proxy)
    if let Some(ref pub_url) = env_public_url {
        endpoints.insert(0, NetworkEndpoint {
            id: "configured-public-url".to_string(),
            address: pub_url.clone(),
            host: pub_url.clone(),
            port,
            label: format!("Configured Public FQDN ({})", pub_url),
            is_recommended: true,
            is_routable: true,
            adapter_type: "configured".to_string(),
        });
    }

    // 7. Always include loopback as a fallback option for single-machine local testing
    endpoints.push(NetworkEndpoint {
        id: "loopback-127-0-0-1".to_string(),
        address: format!("http://127.0.0.1:{}", port),
        host: "127.0.0.1".to_string(),
        port,
        label: format!("Localhost / Same Machine Only (127.0.0.1:{})", port),
        is_recommended: false,
        is_routable: false,
        adapter_type: "loopback".to_string(),
    });

    // Determine the recommended endpoint
    let recommended_endpoint = if let Some(ref pub_url) = env_public_url {
        pub_url.clone()
    } else if let Some(rec) = endpoints.iter().find(|e| e.is_recommended && e.is_routable) {
        rec.address.clone()
    } else if let Some(first_routable) = endpoints.iter().find(|e| e.is_routable) {
        first_routable.address.clone()
    } else {
        format!("http://127.0.0.1:{}", port)
    };

    // Ensure only the selected recommended endpoint has is_recommended = true
    for ep in &mut endpoints {
        ep.is_recommended = ep.address == recommended_endpoint;
    }

    NetworkEndpointsResponse {
        recommended_endpoint,
        configured_public_url: env_public_url,
        endpoints,
    }
}
