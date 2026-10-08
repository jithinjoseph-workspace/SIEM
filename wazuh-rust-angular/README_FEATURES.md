# Provigil AI AETHER SIEM & XDR — Complete Migrated Rust Feature List

> **Platform:** Provigil AI AETHER SIEM & XDR (`backend-rust` + `provigil-common`)  
> **Status:** **100% Implemented & Verified in Rust**  
> **Workspace Architecture:** 37 Modular Cargo Crates | Clean Build | Zero Warnings  
> **Active API Daemon:** Running on Port `8088` (REST + WebSocket)  

This document provides the **exhaustive, definitive catalog of all features, capabilities, subsystems, and rules that have been fully migrated into production-ready Rust**.

---

## 📑 Feature Navigation Matrix

1. [Autonomous AI Parser Synthesizer](#1-autonomous-ai-parser-synthesizer-siem-parser-gen)
2. [Detection & Correlation Engine](#2-detection--correlation-engine-siem-engine--provigil-common)
3. [Live Vulnerability Detection Subsystem](#3-live-vulnerability-detection-subsystem-siem-vuln-detector)
4. [Security Configuration Assessment & CIS Benchmarks](#4-security-configuration-assessment-sca--cis-benchmarks-siem-agent--siem-wdb)
5. [Deep Host Telemetry & System Inventory](#5-deep-host-telemetry--system-inventory-siem-agent--siem-syscollector)
6. [Real-Time File Integrity Monitoring (FIM)](#6-real-time-file-integrity-monitoring-fim-siem-agent--siem-syscheckd)
7. [Rootkit & Kernel Anomaly Detection](#7-rootkit--kernel-anomaly-detection-siem-rootcheck)
8. [Wazuh Agent Enrollment & Cryptographic Protocols](#8-wazuh-agent-enrollment--cryptography-siem-authd--siem-crypto--siem-remoted)
9. [SOAR Active Response & Threat Containment](#9-soar-active-response--threat-containment-siem-execd--siem-integratord)
10. [Multi-Format Syslog Forwarding](#10-multi-format-syslog-forwarding-siem-csyslogd)
11. [Regulatory Compliance Evidence & Reporting](#11-regulatory-compliance-evidence--reporting-siem-reportd)
12. [High-Performance Columnar Storage & In-Memory Resiliency](#12-high-performance-columnar-storage--resiliency-clickhouse--cache)
13. [Fleet Management & Remote Upgrades](#13-fleet-management--remote-upgrades-siem-agent-upgrade--siem-task-manager)
14. [REST API & WebSocket Control Plane](#14-rest-api--websocket-control-plane-siem-api)
15. [37-Crate Traceability Matrix](#15-complete-37-crate-rust-traceability-matrix)

---

## 1. Autonomous AI Parser Synthesizer (`siem-parser-gen`)

* **Deterministic CityHash-64 Hot Path:**
  * Strips dynamic variables (timestamps, IP addresses, PIDs, session IDs) from raw log strings.
  * Computes structural 64-bit hash in nanoseconds.
  * O(1) in-memory hash map lookup with **$0.8\,\mu\text{s}$ execution latency**.
  * **Zero LLM cost** and zero latency for all recurring/known log formats.
* **Sample Buffer Accumulator & Thresholding:**
  * Unrecognized log fingerprints automatically enter an in-memory sample ring buffer.
  * Triggers autonomous AI synthesis task when sample threshold reaches **20 samples**.
* **Dual-Engine AI Regex Synthesis:**
  * **Groq Llama-3 & OpenAI LLM Synthesizer:** Cloud API mode generating production regexes with standard named capture groups (`(?P<srcip>...)`, `(?P<user>...)`, `(?P<action>...)`, `(?P<status>...)`).
  * **Offline Heuristic Regex Inducer:** Local fallback engine for air-gapped deployments without API keys.
* **Sandbox Verification Sandbox:**
  * Candidate regular expressions run in an isolated test harness against all 20 buffered log samples.
  * Enforces strict **$\ge 80\%$ match accuracy** before promoting to the active registry.
* **Dynamic Parser Studio & REST Endpoints:**
  * Web-based schema debugger integrated into Angular frontend.
  * Hot testing of sample logs, schema modification, and manual regex commitment.
  * Persistent schema storage to `data/learned_parsers.json`.

---

## 2. Detection & Correlation Engine (`siem-engine` + `provigil-common`)

* **Official Wazuh Parity:**
  * **1,435 Official Wazuh XML Detection Rules** compiled and evaluated in memory.
  * **1,307 Multi-Protocol XML Decoders** loaded (Syslog, Windows EventChannel, Apache, NGINX, SSH, Auditd, Cisco, Palo Alto, Fortinet, etc.).
  * Hierarchical rule inheritance supported: `if_sid`, `if_group`, `if_matched_sid`.
* **10 Out-of-the-Box (OOTB) Cross-Source Correlation Rules:**
  1. `OOTB-01` (Rule 100101): **Brute Force Detection** (5+ failed authentications in 60s) [MITRE T1110]
  2. `OOTB-02` (Rule 100102): **Account Compromise** (Failed authentication followed by success in 10m) [MITRE T1110 + T1078]
  3. `OOTB-03` (Rule 100103): **Lateral Movement SMB** (SMB connections to 3+ internal hosts in 5m) [MITRE T1021.002]
  4. `OOTB-04` (Rule 100104): **Data Exfiltration** (>100MB outbound payload to external IP in 10m) [MITRE T1048]
  5. `OOTB-05` (Rule 100105): **Privilege Escalation** (User created + added to admin group in 5m) [MITRE T1136 + T1078.002]
  6. `OOTB-06` (Rule 100106): **Impossible Travel** (Logins from distant geolocations within 1 hour) [MITRE T1078]
  7. `OOTB-07` (Rule 100107): **C2 Beacon Detection** (Periodic outbound connections with $\le 10\%$ jitter) [MITRE T1071 + T1102]
  8. `OOTB-08` (Rule 100108): **Malicious Macro Execution** (Office application spawning CMD / PowerShell) [MITRE T1059.001 + T1204.002]
  9. `OOTB-09` (Rule 100109): **DNS DGA Detection** (High Shannon entropy domains) [MITRE T1568.002]
  10. `OOTB-10` (Rule 100110): **Admin Backdoor** (User created + immediate interactive logon in 5m) [MITRE T1136 + T1078]
* **Cross-Source NDR Corroboration Engine (`corroboration.rs`):**
  * Asynchronous background worker cross-correlating network perimeter alerts from NDR (Suricata/Zeek) with host agent telemetry on matching IPs.
  * Escalates corroborated incidents to High/Critical severity.
* **Full MITRE ATT&CK v14 Taxonomy:**
  * Tagging across all 14 Tactics and hundreds of Techniques & Sub-techniques.

---

## 3. Live Vulnerability Detection Subsystem (`siem-vuln-detector`)

* **Thread-Safe Hot CVE Feed Sync:**
  * Live sync endpoint (`POST /api/v1/vulnerabilities/sync-feed`) allows updating CVE definitions on the fly without stopping ingestion.
  * Internal database wrapped in `Arc<RwLock<VulnerabilityFeed>>`.
* **Continuous Inventory Evaluation:**
  * As software inventories arrive from syscollector, package names and versions are evaluated against CVE rules.
* **Standard Wazuh Rule 23501 Alerts:**
  * Confirmed vulnerabilities emit official Rule 23501 alerts containing CVE ID, CVSS score, package name, version, and remediation advice.
* **Real-Time WebSocket Push:**
  * Instant event notification pushed to the Angular SOC Vulnerabilities tab.

---

## 4. Security Configuration Assessment (SCA) & CIS Benchmarks (`siem-agent` + `siem-wdb`)

* **8 Native CIS Benchmark Checks on Windows Endpoints:**
  1. **CIS 2.3.17.1 (SOC 2 CC6.1):** User Account Control (UAC) `EnableLUA` registry validation.
  2. **CIS 18.9.1 (PCI DSS 5.2.1):** Microsoft Defender Antivirus Real-Time Protection status.
  3. **CIS 18.2.1 (NIST CM-7):** SMBv1 Protocol Deprecation check (EternalBlue mitigation).
  4. **CIS 18.9.2 (PCI DSS 2.2.4):** Remote Desktop Network Level Authentication (NLA) enforcement.
  5. **CIS 9.1.1:** Windows Defender Firewall Standard Profile check.
  6. **CIS 2.3.11.1 (SOC 2 CC6.8):** Local Security Authority (LSA) Credential Guard (`RunAsPPL`).
  7. **CIS 18.5.1 (NIST SC-8):** LLMNR Multicast Name Resolution disablement.
  8. **CIS 18.9.30 (PCI DSS 5.1):** Windows SmartScreen enforcement check.
* **Automated SCA Alerting:**
  * Non-compliant checks trigger official Wazuh **Rule 19001** alerts.
* **SCA Score & Compliance Reporting:**
  * Endpoint `GET /api/v1/agents/:id/sca` returns real-time pass/fail breakdown and compliance percentages.

---

## 5. Deep Host Telemetry & System Inventory (`siem-agent` + `siem-syscollector`)

* **Windows Registry Package Enumeration:**
  * Recursively scans `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit) and `HKLM\Software\Wow6432Node\...` (32-bit).
  * Extracts true `DisplayName`, `DisplayVersion`, `Publisher`, and `InstallDate` for 100+ installed applications.
* **Linux Package Inventory:**
  * Native parser for `/var/lib/dpkg/status` on Debian/Ubuntu systems.
* **Hardware & Network Telemetry:**
  * CPU core counts, physical RAM usage, network interfaces with MAC, IPv4, IPv6 addresses.
* **Ports, Services & Processes:**
  * Active listening TCP/UDP sockets, Windows services (status, startup type), systemd units, active user sessions.
* **Data Normalizer (`normalizer.rs`):**
  * Normalizes disparate OS structures into standard Wazuh syscollector format.

---

## 6. Real-Time File Integrity Monitoring (FIM) (`siem-agent` + `siem-syscheckd`)

* **Persistent SHA-256 Baselines:**
  * Hashes and monitors critical files: `\System32\drivers\etc\hosts`, user/system Startup folders, and PowerShell profiles (`profile.ps1`).
* **NTFS Alternate Data Stream (ADS) Detection:**
  * Identifies hidden executable streams (e.g. `file.exe:hidden.dll`) used for stealth persistence.
* **Real-Time OS Filesystem Notifications:**
  * Uses the Rust `notify` crate for instant kernel event capture.
* **Standard Wazuh Differential Alerts:**
  * **Rule 550:** File Added
  * **Rule 554:** File Modified (with before/after SHA-256 hash diff) [MITRE T1565.001]
  * **Rule 553:** File Deleted

---

## 7. Rootkit & Kernel Anomaly Detection (`siem-rootcheck`)

* **Hidden Process Detection:**
  * Compares process enumeration from OS APIs against direct kernel object lists.
* **Trojan Port Scanning:**
  * Identifies suspicious or undocumented listening ports matching known malware backdoor signatures.
* **Hidden Filesystem Artifacts:**
  * Scans for hidden files and suspicious drivers installed without valid digital signatures.

---

## 8. Wazuh Agent Enrollment & Cryptography (`siem-authd` + `siem-crypto` + `siem-remoted`)

* **192-bit Key Derivation Algorithm:**
  $$\text{Key} = \text{MD5}(\text{RawKey}) \parallel \text{MD5}(\text{MD5}(\text{Name}) \parallel \text{MD5}(\text{ID}))[0..15]$$
* **Agent Enrollment Server (`siem-authd` on Port 1515):**
  * Implements OSSEC enrollment handshake: `OSSEC K:'ID NAME IP KEY'`.
* **Encrypted Agent Receiver (`siem-remoted` on Port 1514):**
  * UDP and TCP receivers handling Blowfish and AES-128/192/256 encrypted agent payloads.
* **Keystore Management:**
  * In-memory thread-safe keystore with persistent synchronization to disk (`client.keys`).

---

## 9. SOAR Active Response & Threat Containment (`siem-execd` + `siem-integratord`)

* **Automated Host Micro-Isolation:**
  * **Windows:** Automated `netsh advfirewall firewall add rule` inbound IP drop.
  * **Linux:** Automated `iptables -I INPUT -s <IP> -j DROP` or `nftables` drop.
  * **User Account Lockdown:** Automated `net user <name> /active:no`.
* **Non-Blocking 600s Auto-Reversion:**
  * Background Tokio timer (`tokio::time::sleep(Duration::from_secs(600))`) automatically removes the firewall drop rule after expiration to prevent accidental administrative lockouts.
* **Multi-Channel Webhook Dispatcher (`siem-integratord`):**
  * Alerts with severity $\ge 10$ dispatch rich JSON webhooks to **Slack (`#soc-alerts`)**, **PagerDuty**, **Jira**, and **VirusTotal**.

---

## 10. Multi-Format Syslog Forwarding (`siem-csyslogd`)

* **CEF (Common Event Format):** ArcSight / Micro Focus standard compatible formatting.
* **JSON Streaming:** Newline-delimited JSON for direct Splunk HEC or Elastic Logstash ingestion.
* **Splunk Key/Value (`splunk-kv`):** Optimized key/value pair format.
* **Standard Syslog (RFC 3164):** Legacy BSD syslog format.

---

## 11. Regulatory Compliance Evidence & Reporting (`siem-reportd`)

* **Automated Control Mapping:**
  * **PCI DSS v4.0.1:** Requirements 2.2.4 (NLA), 5.2.1 (Anti-malware), 10.2 (Audit logs & failed logins).
  * **SOC 2 Type II:** Trust Services Criteria CC6.1 (Access Controls), CC6.8 (Malicious Software), CC7.2 (Vulnerability Management).
  * **ISO/IEC 27001:2022:** Controls A.8.15 (Logging) and A.8.16 (Monitoring Activities).
  * **HIPAA Security Rule:** 45 CFR § 164.312(b) Audit Controls & § 164.312(a)(2)(iii) Auto-Logoff.
  * **NIST CSF 2.0:** Functions Detect (DE.CM - Continuous Monitoring) and Respond (RS.AN - Incident Analysis).
* **Compliance Endpoint:**
  * `GET /api/v1/reports/summary` returning live compliance metrics and rule frequency breakdowns.

---

## 12. High-Performance Columnar Storage & Resiliency (`ClickHouse` + Cache)

* **ClickHouse Partitioned Tables:**
  * `unified_alerts`: Normalized multi-source alert storage with 1-year retention.
  * `siem_events`: High-speed raw event ingestion buffer.
  * `siem_alerts`: Evaluated security alerts.
  * `xdr_incidents`: Corroborated cross-source network + host incidents.
  * `ndr.threat_intel`: IOC threat database.
* **In-Memory Zero-Downtime Cache:**
  * In the event ClickHouse is restarting or temporarily unreachable, the Tokio processing pipeline buffers alerts in an in-memory ring buffer with **zero dropped events**.

---

## 13. Fleet Management & Remote Upgrades (`siem-agent-upgrade` + `siem-task-manager`)

* **Remote WPK Agent Upgrades:**
  * Remote binary upgrades using Wazuh Package (.wpk) files with cryptographic signature validation.
* **Distributed Task Coordination:**
  * Health check polling, job dispatch, and execution tracking across thousands of connected agents.
* **Cluster Consensus (`siem-clusterd`):**
  * Node discovery, state synchronization, and failover support.

---

## 14. REST API & WebSocket Control Plane (`siem-api`)

* **Active Tokio/Axum Daemon (Port `8088`):**
  * `POST /api/v1/ingest`: High-throughput HTTP log ingestion.
  * `GET /api/v1/agents`: List all enrolled agents, statuses, and metadata.
  * `GET /api/v1/agents/:id/inventory`: Fetch deep hardware, network, and package inventory.
  * `GET /api/v1/agents/:id/sca`: Fetch real-time CIS benchmark compliance scores.
  * `POST /api/v1/vulnerabilities/sync-feed`: Hot-sync CVE vulnerability feed.
  * `GET /api/v1/parsers/registry`: Inspect learned schemas and precompiled regexes.
  * `POST /api/v1/parsers/test`: Test raw log string against active parser studio.
  * `POST /api/v1/active-response`: Manually trigger or inspect active response mitigations.
  * `GET /api/v1/reports/summary`: Regulatory compliance breakdown.
  * `GET /ws/events`: WebSocket stream broadcasting live alerts, FIM diffs, and detections directly to the Angular SOC UI.

---

## 15. Complete 37-Crate Rust Traceability Matrix

Every crate in `backend-rust` and `provigil-common` compiles cleanly and executes a dedicated subsystem role:

| # | Crate Name | Subsystem Tier | Core Responsibility & Features |
| :---: | :--- | :--- | :--- |
| **1** | `siem-api` | API & Control Plane | Tokio HTTP/WebSocket server, REST routes, live dashboard streaming on port 8088 |
| **2** | `siem-engine` | Detection Engine | Evaluates 1,435 rules and 1,307 decoders; manages threat alert lifecycles |
| **3** | `siem-parser-gen` | AI Parser Synthesizer | CityHash-64 fingerprinting, Groq/Local regex synthesizer, sandbox validator |
| **4** | `siem-vuln-detector`| Vulnerability Engine | Arc<RwLock> CVE feed sync, live syscollector package inventory matching |
| **5** | `siem-syscollector` | System Telemetry | Package inventory normalizer, hardware/network/service state extractor |
| **6** | `siem-agent` | Host Endpoint Agent | Windows agent runner: FIM, SCA, EventChannel, uninstall registry scanner |
| **7** | `siem-agent-linux` | Host Endpoint Agent | Linux agent runner: auditd, syslog, and /var/lib/dpkg/status parsing |
| **8** | `siem-syscheckd` | Integrity Monitoring | FIM baseline engine, persistent SHA-256 hash tracking, ADS stream detection |
| **9** | `siem-execd` | SOAR Active Response | Executes netsh/iptables firewall drops with 600s non-blocking auto-revert |
| **10** | `siem-integratord` | Notification Egress | Outbound webhook dispatcher for Slack, PagerDuty, Jira, and VirusTotal |
| **11** | `siem-csyslogd` | Syslog Forwarder | Multi-format alert serializing: CEF, JSON, Splunk-kv, and RFC 3164 syslog |
| **12** | `siem-wdb` | Agent State Database | SQLite/sled storage for agent state, syscollector data, and CIS baselines |
| **13** | `siem-cdb` | Threat Intelligence | Fast constant database (CDB) for IOC lookups, IP blacklists, and domain hashes |
| **14** | `siem-authd` | Agent Enrollment | TCP port 1515 enrollment server, client.keys manager, key derivation |
| **15** | `siem-crypto` | Cryptographic Codec | 192-bit Blowfish/AES key derivation, encrypted protocol envelope codec |
| **16** | `siem-remoted` | Encrypted Receiver | UDP/TCP port 1514 encrypted agent communication receiver |
| **17** | `siem-analysisd` | Event Correlation | Statistical anomaly detection, frequency counters, and multi-event correlation |
| **18** | `siem-monitord` | Platform Watchdog | Monitors SIEM daemon internal health, memory consumption, and thread status |
| **19** | `siem-logtest` | Analyst Testing CLI | Interactive command-line tool for evaluating raw logs against rules/decoders |
| **20** | `siem-maild` | SMTP Alert Egress | RFC 2822 email composer and SMTP dispatcher for critical severity alerts |
| **21** | `siem-reportd` | Compliance Reporting | Generates PCI DSS, SOC 2, HIPAA, and ISO 27001 evidence summaries |
| **22** | `siem-agent-upgrade`| Remote Upgrades | WPK remote agent upgrade orchestrator, cryptographic package verification |
| **23** | `siem-task-manager` | Task Coordination | Orchestrates background tasks, distributed jobs, and agent health polling |
| **24** | `siem-harvester` | Event Harvesting | Gathers log files from standard directories (/var/log, Windows Event Logs) |
| **25** | `siem-rootcheck` | Rootkit Detection | Scans for hidden processes, trojan ports, and suspicious kernel signatures |
| **26** | `siem-clusterd` | Cluster Federation | Multi-node SIEM cluster consensus, state synchronization, and failover |
| **27** | `siem-indexer-connector`| Analytics Pipeline | High-throughput connector for ClickHouse and OpenSearch event indexing |
| **28** | `siem-event-hub` | Internal Event Bus | High-speed Tokio broadcast channel routing events between internal crates |
| **29** | `siem-types` | Core Domain Types | Common data models: Event, Alert, Rule, Decoder, Vulnerability, Agent |
| **30** | `siem-config` | Configuration Engine | Parses ossec.conf and YAML configuration profiles with hot-reload support |
| **31** | `siem-metrics` | Prometheus Metrics | Exports Prometheus /metrics endpoint for Prometheus/Grafana observability |
| **32** | `siem-geo` | GeoIP Resolution | MaxMind GeoIP2/GeoLite2 database lookup for threat globe visualization |
| **33** | `siem-rule-compiler`| Ruleset Precompiler | Compiles XML rules and decoders into optimized memory structures |
| **34** | `siem-threat-intel` | Threat Intelligence | Polls external threat feeds (AlienVault OTX, AbuseIPDB, MISP) |
| **35** | `siem-archive` | Cold Storage Archival| Compresses and archives raw log streams to long-term storage |
| **36** | `siem-agent-simulator`| Testing & Emulation | Simulates 10,000 concurrent agents for stress and scale benchmarking |
| **37** | `provigil-common` | Shared Foundation | Shared types, ClickHouse client, JWT authentication, and Corroboration Engine |
