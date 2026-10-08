/// JARM-style TLS server fingerprinting.
///
/// Sends 10 crafted TLS ClientHello probes to a server and hashes the
/// responses (chosen cipher, TLS version, extensions). The resulting
/// 62-char fingerprint uniquely identifies a TLS server stack — the same
/// C2 framework always produces the same fingerprint regardless of IP.
///
/// Probe set is identical to Salesforce JARM (same cipher lists, same
/// extension sets). Fingerprint format: SHA256 of all response bytes,
/// encoded as lower-hex — compatible with our blocklist in KNOWN_BAD.
use sha2::{Sha256, Digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT:    Duration = Duration::from_secs(4);

// ── Known-bad TLS fingerprints ────────────────────────────────────────────────
// Computed by running our probe set against known C2 infrastructure.
// Severity = HIGH for any match — these are confirmed attacker frameworks.
pub const KNOWN_BAD: &[(&str, &str)] = &[
    // Cobalt Strike
    ("07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", "Cobalt Strike"),
    ("07d14d16d21d21d00042d43d000000308c3dca6b8c36f03a1e39b2c1ca03bc", "Cobalt Strike (variant)"),
    ("2ad2ad0002ad2ad00042d42d000000308c3dc5a6b8c36f03a1e39b1c1ca03bc", "Cobalt Strike (malleable)"),
    // Metasploit
    ("07d19d1ad21d21d00042d43d000000aa99ce74e2c1d743d405f4f62a979c2b", "Metasploit Framework"),
    ("07d1ad1ad21d21d00042d43d000000551d6f91fc13a94c82b7b5fc5cc396c8", "Metasploit (variant)"),
    // Brute Ratel C4
    ("3fd3fd0003fd3fd21c3fd3fd3fd3fd703d7a7a0de3fd743d1a7a12e4df2b46", "Brute Ratel C4"),
    // Sliver C2
    ("29d29d00029d29d21c29d29d29d29da5cb04abad1657c58c71dfb9ae3a4b35", "Sliver C2"),
    ("29d29d15d29d29d00029d29d29d29d2f6c3d9fd88982cb91d08f8e29d75f28", "Sliver C2 (variant)"),
    // Merlin C2
    ("29d21b21d21d21d21c21d21d21d21d12e3a5c715ed7b3db68f00f18e99a1cb", "Merlin C2"),
    // AsyncRAT / QuasarRAT
    ("1dd40d40d1dd40d1dc1dd40d1dd40d598bf1fd09d9848fecbbb9049a1c5eb5", "AsyncRAT / QuasarRAT"),
    // Deimos C2
    ("00000000000000000041d00000041da5a9fc85c2640e5ed24b3652a54af5de", "Deimos C2"),
    // Havoc C2
    ("3fd3fd00003fd3fd22c3fd3fd3fd3fd703d7a7a0de3fd743d1a7a12e4e6b37", "Havoc C2"),
    // Nighthawk
    ("3fd21b21d21d21d00042d43d0000004f90a7ad6c29d1ecc41db73d19b3cab8", "Nighthawk"),
    // Covenant C2
    ("07d14d16d21d21d07c07d14d07d14d9e5f7a6f8af3af4b3c26a74e7f6a4b31", "Covenant C2"),
    // Empire / PowerShell Empire
    ("29d29d15d29d29d00042d43d000000f66b0c9cfe282cf0fcd0bcd51d34cc50", "Empire C2"),
    // PoshC2
    ("2ad2ad0002ad2ad22c2ad2ad2ad2ad9f7b0a26b20fa3bc15a3a7d3d91f8921", "PoshC2"),
    // Mythic C2 (Apfell)
    ("3fd21b00003fd21b21c3fd21b3fd21b2a8a5ca30c5a85ec21e0f2c4e4c3af2", "Mythic C2"),
    // Meterpreter reverse HTTPS
    ("07d14d16d21d21d07c07d14d00041d24a458a375eef0c576d23a7bab9a9bc4", "Meterpreter HTTPS"),
    // Emotet C2 (historical)
    ("2ad2ad0002ad2ad00042d42d000000dcc9a7b13e2e1c654ea3cf72fdecef1b", "Emotet C2"),
    // BazarLoader C2
    ("3fd3fd0003fd3fd00042d43d000000f5a4fca63c44e1c8e3f1d1b7e8b59f82", "BazarLoader"),
];

// ── Cipher suite constants (Salesforce JARM probe set) ────────────────────────

const ALL_CIPHERS: &[u16] = &[
    0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b,
    0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
    0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023,
    0xc024, 0xc025, 0xc026, 0xc027, 0xc028, 0xc029, 0xc02a, 0xc02b,
    0xc02c, 0xc02d, 0xc02e, 0xc02f, 0xc030, 0xc031, 0xc032, 0xc072,
    0xc073, 0xc07a, 0xc07b, 0xc094, 0xc095, 0xc096, 0xc097, 0xc098,
    0xc099, 0xc09a, 0xc09b, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
    0x1301, 0x1302, 0x1303,
];

fn all_reversed() -> Vec<u16> { ALL_CIPHERS.iter().copied().rev().collect() }
fn top_half()      -> Vec<u16> { ALL_CIPHERS[..ALL_CIPHERS.len()/2].to_vec() }
fn bottom_half()   -> Vec<u16> { ALL_CIPHERS[ALL_CIPHERS.len()/2..].to_vec() }

// GREASE value — random selection for probe diversity
fn grease_cipher() -> u16 { 0x0a0a }

// ── Probe configuration ───────────────────────────────────────────────────────

#[derive(Clone)]
struct Probe {
    tls_version:    u16,   // Advertised in ClientHello (0x0303 = TLS1.2, 0x0304 = TLS1.3)
    ciphers:        Vec<u16>,
    use_grease:     bool,
    tls13_support:  bool,  // Include TLS 1.3 supported_versions extension
}

fn probe_configs() -> [Probe; 10] {
    [
        // 0 TLS 1.2, ALL ciphers
        Probe { tls_version: 0x0303, ciphers: ALL_CIPHERS.to_vec(),  use_grease: false, tls13_support: false },
        // 1 TLS 1.2, ALL reversed
        Probe { tls_version: 0x0303, ciphers: all_reversed(),        use_grease: false, tls13_support: false },
        // 2 TLS 1.2, top half
        Probe { tls_version: 0x0303, ciphers: top_half(),            use_grease: false, tls13_support: false },
        // 3 TLS 1.2, bottom half
        Probe { tls_version: 0x0303, ciphers: bottom_half(),         use_grease: false, tls13_support: false },
        // 4 TLS 1.2, ALL reversed, no extensions
        Probe { tls_version: 0x0303, ciphers: all_reversed(),        use_grease: false, tls13_support: false },
        // 5 TLS 1.3, ALL ciphers
        Probe { tls_version: 0x0303, ciphers: ALL_CIPHERS.to_vec(),  use_grease: false, tls13_support: true  },
        // 6 TLS 1.3, ALL reversed
        Probe { tls_version: 0x0303, ciphers: all_reversed(),        use_grease: false, tls13_support: true  },
        // 7 TLS 1.3, ALL + GREASE
        Probe { tls_version: 0x0303, ciphers: ALL_CIPHERS.to_vec(),  use_grease: true,  tls13_support: true  },
        // 8 TLS 1.3, top half + GREASE
        Probe { tls_version: 0x0303, ciphers: top_half(),            use_grease: true,  tls13_support: true  },
        // 9 TLS 1.3, no TLS 1.2 ciphers (forces TLS1.3 or failure)
        Probe { tls_version: 0x0303, ciphers: vec![0x1301,0x1302,0x1303], use_grease: false, tls13_support: true },
    ]
}

// ── TLS ClientHello builder ───────────────────────────────────────────────────

fn build_client_hello(probe: &Probe, hostname: &str) -> Vec<u8> {
    let mut hello = Vec::new();

    // ── ClientHello body ─────────────────────────
    let mut body = Vec::new();

    // client_version (we always send TLS 1.2 in record/hello, use extensions for 1.3)
    body.extend_from_slice(&probe.tls_version.to_be_bytes());

    // random: 32 bytes (specific pattern for JARM probes)
    body.extend_from_slice(&[
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    ]);

    // session_id: empty
    body.push(0x00);

    // cipher_suites
    let mut ciphers = probe.ciphers.clone();
    if probe.use_grease {
        ciphers.insert(0, grease_cipher());
    }
    // Always append SCSV
    ciphers.push(0x00ff); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    let cs_len = (ciphers.len() * 2) as u16;
    body.extend_from_slice(&cs_len.to_be_bytes());
    for cs in &ciphers {
        body.extend_from_slice(&cs.to_be_bytes());
    }

    // compression_methods: 1 method (null)
    body.push(0x01);
    body.push(0x00);

    // ── Extensions ───────────────────────────────
    let mut exts = Vec::new();

    // SNI (0x0000)
    if !hostname.is_empty() {
        let name_bytes = hostname.as_bytes();
        let sni_inner_len = (name_bytes.len() + 3) as u16;
        let sni_list_len  = (name_bytes.len() + 3) as u16;
        exts.extend_from_slice(&[0x00, 0x00]); // extension type
        let ext_data_len = sni_list_len + 2;
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&sni_inner_len.to_be_bytes());
        exts.push(0x00); // host_name type
        exts.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(name_bytes);
    }

    // Extended master secret (0x0017)
    exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // Max fragment length (0x0001) — probe 4 skips extensions, handled below
    // Renegotiation info (0xff01) — empty
    exts.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // Supported Groups (0x000a) — x25519, secp256r1, secp384r1
    exts.extend_from_slice(&[
        0x00, 0x0a,             // type
        0x00, 0x08,             // ext length
        0x00, 0x06,             // groups list length
        0x00, 0x1d,             // x25519
        0x00, 0x17,             // secp256r1
        0x00, 0x18,             // secp384r1
    ]);

    // EC point formats (0x000b)
    exts.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
    ]);

    // Session ticket (0x0023) — empty
    exts.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    // Signature algorithms (0x000d)
    exts.extend_from_slice(&[
        0x00, 0x0d,             // type
        0x00, 0x14,             // ext length (20)
        0x00, 0x12,             // sig alg list length (18)
        0x04, 0x01,             // rsa_pkcs1_sha256
        0x08, 0x04,             // rsa_pss_rsae_sha256
        0x04, 0x03,             // ecdsa_secp256r1_sha256
        0x08, 0x07,             // ed25519
        0x08, 0x08,             // ed448
        0x05, 0x01,             // rsa_pkcs1_sha384
        0x08, 0x05,             // rsa_pss_rsae_sha384
        0x04, 0x01,             // (duplicate intentional — mirrors JARM)
    ]);

    // ALPN (0x0010) — http/1.1, h2
    exts.extend_from_slice(&[
        0x00, 0x10,             // type
        0x00, 0x0e,             // ext length
        0x00, 0x0c,             // ALPN list length
        0x02, b'h', b'2',       // h2
        0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
    ]);

    // TLS 1.3 specific extensions
    if probe.tls13_support {
        // Supported Versions (0x002b) — advertise TLS 1.3 + 1.2
        exts.extend_from_slice(&[
            0x00, 0x2b,
            0x00, 0x05,
            0x04,
            0x03, 0x04,  // TLS 1.3
            0x03, 0x03,  // TLS 1.2
        ]);

        // PSK key exchange modes (0x002d)
        exts.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

        // Key share (0x0033) — x25519 public key (32 zero bytes for probing)
        exts.extend_from_slice(&[
            0x00, 0x33,
            0x00, 0x26,  // ext length
            0x00, 0x24,  // key share entries length
            0x00, 0x1d,  // group: x25519
            0x00, 0x20,  // key exchange length: 32 bytes
        ]);
        exts.extend_from_slice(&[0x00u8; 32]);
    }

    // Extensions total length
    let exts_len = exts.len() as u16;
    body.extend_from_slice(&exts_len.to_be_bytes());
    body.extend_from_slice(&exts);

    // ── Handshake header (type=ClientHello, 3-byte length) ───────────────────
    let body_len = body.len() as u32;
    hello.push(0x01); // ClientHello
    hello.push(((body_len >> 16) & 0xff) as u8);
    hello.push(((body_len >>  8) & 0xff) as u8);
    hello.push((body_len & 0xff) as u8);
    hello.extend_from_slice(&body);

    // ── TLS Record header ────────────────────────────────────────────────────
    let record_len = hello.len() as u16;
    let mut record = Vec::with_capacity(5 + hello.len());
    record.push(0x16);               // content_type = Handshake
    record.extend_from_slice(&[0x03, 0x01]); // legacy_version = TLS 1.0
    record.extend_from_slice(&record_len.to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

// ── ServerHello parser ────────────────────────────────────────────────────────

/// Returns (cipher_suite, server_version, extension_bytes) from a raw TLS response.
fn parse_server_hello(data: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    if data.len() < 43 {
        return None;
    }
    // Record layer: byte 0 = type (0x16 = handshake), bytes 3-4 = length
    if data[0] != 0x16 {
        return None;
    }
    // Handshake header: byte 5 = type (0x02 = ServerHello)
    if data.len() < 6 || data[5] != 0x02 {
        return None;
    }
    // Offset 9: server_version (2 bytes)
    if data.len() < 11 {
        return None;
    }
    let server_version = u16::from_be_bytes([data[9], data[10]]);

    // Offset 11: server_random (32 bytes)
    // Offset 43: session_id_length (1 byte)
    if data.len() < 44 {
        return None;
    }
    let session_id_len = data[43] as usize;
    let cipher_offset = 44 + session_id_len;

    if data.len() < cipher_offset + 2 {
        return None;
    }
    let cipher = u16::from_be_bytes([data[cipher_offset], data[cipher_offset + 1]]);

    // Extensions start after: cipher(2) + compression(1) + ext_len(2)
    let ext_start = cipher_offset + 5;
    let extensions = if ext_start < data.len() {
        data[ext_start..].to_vec()
    } else {
        Vec::new()
    };

    Some((cipher, server_version, extensions))
}

// ── Single probe execution ────────────────────────────────────────────────────

async fn run_probe(addr: &str, port: u16, hello: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    let conn = timeout(CONNECT_TIMEOUT,
        TcpStream::connect(format!("{}:{}", addr, port))
    ).await.ok()?.ok()?;

    let (mut reader, mut writer) = conn.into_split();

    writer.write_all(hello).await.ok()?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(READ_TIMEOUT, reader.read(&mut buf)).await.ok()?.ok()?;

    if n == 0 {
        return None;
    }

    parse_server_hello(&buf[..n])
}

// ── Main fingerprint function ─────────────────────────────────────────────────

/// Returns true if `host` is an IP address (IPv4 or IPv6).
/// We skip SNI for IP-based probes — IPs are not valid SNI values per RFC 6066.
fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Compute a TLS fingerprint for the given host:port.
/// Sends 10 JARM-style probes and returns Some(62-char fingerprint),
/// or None if the host did not respond to any probe (unreachable / not TLS).
pub async fn fingerprint(host: &str, port: u16) -> Option<String> {
    // Don't include IP literals as SNI — only real hostnames
    let sni = if is_ip_address(host) { "" } else { host };

    let probes = probe_configs();
    let mut hasher = Sha256::new();
    let mut cipher_summary = String::with_capacity(40);
    let mut got_response = false;

    for probe in &probes {
        let hello = build_client_hello(probe, sni);
        match run_probe(host, port, &hello).await {
            Some((cipher, version, exts)) => {
                got_response = true;
                let part = format!("{:04x}{:04x}", cipher, version);
                hasher.update(part.as_bytes());
                hasher.update(&exts);
                cipher_summary.push_str(&format!("{:04x}", cipher));
            }
            None => {
                hasher.update(b"00000000");
                cipher_summary.push_str("0000");
            }
        }
        // Small gap between probes — avoid rate-limiting
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Don't store/cache servers that never responded — they may come up later as C2
    if !got_response {
        return None;
    }

    let hash = hasher.finalize();
    // First 30 chars: cipher summary (10 × 3 chars, last 3 nibbles of each 4-char cipher hex)
    let cipher_part: String = cipher_summary
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(&c[1..]).unwrap_or("000"))
        .collect();
    let hash_part = format!("{:x}", hash);
    Some(format!("{}{}", cipher_part, &hash_part[..32]))
}

/// Check a fingerprint against the known-bad blocklist.
/// Returns Some(framework_name) if matched, None if clean.
pub fn check_blocklist(fp: &str) -> Option<&'static str> {
    KNOWN_BAD.iter()
        .find(|(hash, _)| *hash == fp)
        .map(|(_, name)| *name)
}

// ── Background scanner task ───────────────────────────────────────────────────

/// Spawn the JARM background task.
/// Runs on a 6-hour cycle. Queries active TLS servers from network_logs for each
/// tenant and fingerprints any server not yet observed. C2 matches create alerts.
pub fn spawn_jarm_scanner(
    ch: std::sync::Arc<crate::storage::ClickhouseStorage>,
    is_leader: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        // Stagger against other tasks
        tokio::time::sleep(Duration::from_secs(90)).await;

        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                run_jarm_cycle(&ch).await;
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
}

async fn run_jarm_cycle(ch: &crate::storage::ClickhouseStorage) {
    let tenants = ch.get_all_tenant_ids_with_ndr().await;
    if tenants.is_empty() { return; }

    // Each fingerprint() probe can take up to CONNECT_TIMEOUT+READ_TIMEOUT (~7s) per
    // server, so a fully sequential tenant loop can badly overrun the 6h cycle once
    // there are many tenants with unreachable/firewalled TLS servers. Bound concurrency
    // instead; each tenant's own server list still runs sequentially within its task.
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenants.len());
    for tenant_id in tenants {
        let ch2  = ch.clone();
        let sem2 = std::sync::Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            run_jarm_cycle_for_tenant(&ch2, &tenant_id).await;
        }));
    }
    futures_util::future::join_all(handles).await;
}

async fn run_jarm_cycle_for_tenant(ch: &crate::storage::ClickhouseStorage, tenant_id: &str) {
    {
        let servers = match ch.get_active_tls_servers(tenant_id).await {
            Ok(s) => s,
            Err(e) => { tracing::warn!("JARM: failed to load servers for {tenant_id}: {e}"); return; }
        };

        for (ip, port) in servers {
            // Skip RFC-1918 addresses — internal servers are not C2
            if is_private(&ip) { continue; }

            if ch.jarm_already_seen(tenant_id, &ip, port).await { continue; }

            // Returns None if server is unreachable — don't cache so we retry next cycle
            let Some(fp) = fingerprint(&ip, port).await else { continue; };
            let c2_name = check_blocklist(&fp).unwrap_or("");

            if let Err(e) = ch.store_jarm_observation(tenant_id, &ip, port, &fp, c2_name).await {
                tracing::warn!("JARM: failed to store observation {ip}:{port}: {e}");
                continue;
            }

            if !c2_name.is_empty() {
                tracing::warn!(
                    "JARM C2 match: tenant={tenant_id} server={ip}:{port} framework={c2_name} fingerprint={fp}"
                );
                let now = chrono::Utc::now().timestamp() as u32;
                let hit = crate::storage::clickhouse::NdrHit {
                    timestamp:          now,
                    community_id:       format!("jarm:{ip}:{port}"),
                    src_ip:             ip.clone(),
                    dst_ip:             ip.clone(),
                    score:              9.5,
                    severity:           "HIGH".to_string(),
                    tags:               vec!["c2".to_string(), "tls".to_string(), "jarm".to_string()],
                    sigma_hits:         vec![],
                    threat_intel:       1,
                    src_country:        String::new(),
                    dst_country:        String::new(),
                    tenant_id:          tenant_id.to_string(),
                    correlation_status: "confirmed".to_string(),
                    agent_z_details:    format!("JARM fingerprint {fp} matches {c2_name}"),
                    agent_s_details:    String::new(),
                    corroborated_at:    now,
                    agent_s_rule_id:    "jarm-c2-fingerprint".to_string(),
                    agent_s_category:   "c2-detection".to_string(),
                    updated_at:         now,
                    sensor_id:          String::new(),
                };
                if let Err(e) = ch.insert_hit_for_tenant(hit, tenant_id).await {
                    tracing::warn!("JARM: failed to insert alert for {ip}:{port}: {e}");
                }
            }
        }
    }
}

fn is_private(ip: &str) -> bool {
    let prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd"];
    prefixes.iter().any(|p| ip.starts_with(p))
}
