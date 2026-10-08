# NDR Platform — Full Feature Catalogue

> **Positioning:** The only multi-tenant Network Detection & Response platform built for the next generation of cyber threats — combining AI-driven behavioral intelligence, real-time topology awareness, and full-fidelity packet forensics in a single unified console.

---

## 1. Security Command Center — Live SOC Dashboard

**Everything your SOC needs to know, the moment it happens. Zero delay, zero polling.**

- Real-time stat cards driven by WebSocket telemetry: total network events, correlation hits, Agent-Z events, Agent-S events, and hour-over-hour deltas — all updating live without a page refresh
- Live event stream area chart: D3.js animated area graph of event volume across time with interactive tooltips per data point
- Severity donut chart: interactive D3 breakdown of Critical / High / Medium / Low alerts with hover-expand slices and a live total counter in the centre
- Protocol distribution pie: real-time breakdown of traffic by application protocol (TCP, DNS, HTTP, TLS, UDP, and more)
- Top destination IPs bar chart: animated horizontal bar chart of the 5 highest-volume external destinations, colour-coded with gradient fills
- Alert severity counters: live-updating Critical, High, Medium, Low badge counts with WebSocket increment on every incoming hit
- Threat prediction banner: active ML-predicted attack types displayed as dismissible alerts — click any prediction for historical trend detail
- Source/destination IP intelligence: top talkers ranked by connection volume, refreshed via telemetry push
- Direct navigation shortcuts: one click to AI Report, Alert Console, or Network Map from any dashboard card
- SWR (stale-while-revalidate) chart caching: chart renders instantly from cached data on page load, then silently refreshes in the background
- Export to report: one-click navigation to the full AI-generated security report

---

## 2. Alert Triage & Incident Management

**Every detection, triaged by threat pattern. Every incident, one click away.**

- Intelligent alert grouping: alerts automatically clustered by detection tag, source IP, and destination IP — one row per attacker-target path, not one row per event
- 28+ detection tag categories: dns-beaconing, port-scan, lateral-movement, credential-stuffing, beaconing, threat-intel, ids-alert, data-staging, internal-recon, volume-anomaly, dga, doh-evasion, malicious-domain, tls-cert-anomaly, protocol-misuse, sigma, and more
- Multi-dimensional filtering: severity (Critical / High / Medium / Low), detection tag, minimum risk score, and free-text IP / description search
- Entity risk scores panel: ranked list of the highest-risk IPs observed in your network — click any host to instantly pin the alert view to that IP
- PCAP in-context: click any alert to open the packet capture for that session without leaving the alert console
- One-click block: submit a manual block rule (RST / firewall enforcement) directly from an alert row
- Group suppress: silence an entire attack group from a specific source with one click — suppression sent to backend, deduplicated in future WebSocket streams
- Sigma-aware suppression: Sigma multi-rule groups suppress each rule individually, never creating a blanket silence
- Trust domain action: mark a flagged DNS destination as trusted directly from the alert — removes future noise from that domain
- Create incident: promote any alert or group to a tracked SOAR case with pre-filled metadata (severity, IPs, tags, Sigma hits)
- Incident tab: full case list view inside the alerts console — open, track, and manage cases without switching pages
- Device isolation from incident: isolate a host directly from an open incident detail panel
- Real-time alert streaming: new hits arrive via WebSocket `continuousHits$` and merge into the live alert list without duplicates
- Community ID tracking: every alert carries an RFC-5952 community ID for cross-tool correlation with SIEM / PacketVault

---

## 3. Threat Intelligence Hub

**Your network's threat exposure — measured, mapped, and actionable.**

- IOC lookup: search any IP, domain, file hash, JA3 fingerprint, or URL against the live threat intelligence database in real time
- Multi-source feed aggregation: malicious IPs, file hashes, and domain/URL feeds from multiple threat intelligence sources (abuse.ch and others)
- Feed statistics dashboard: total malicious IPs, hashes, and domains in the active feed, with source attribution and last-refresh timestamp
- Detected-in-network table: IPs observed in your traffic that match threat intelligence — sortable by hit count or last seen, exportable to CSV
- Manual IOC watchlist: add custom threat indicators by type (IP / domain / hash / JA3 / URL) with optional attacker group attribution
- Watchlist management: view, search, filter, and delete all manual IOC entries
- Geo intelligence tab: top 15 attack-origin countries ranked by hit count, visualised as relative progress bars with country flag emoji
- Live alert sync: threat intel hits pushed via the platform's real-time notification bus appear instantly in the detected-in-network panel
- IOC export: download the filtered detected-network table as a timestamped CSV for offline analysis or SIEM import
- 15-second auto-refresh: intelligence dashboard stays current without manual intervention

---

## 4. Neural Topology Engine

**Real-time, self-organizing network map that shows you every host, every connection, every threat — as it happens.**

- Live force-directed graph renders your entire network in real time — nodes, edges, and traffic volumes update without page refresh
- Cluster auto-expansion: dense host groups collapse into smart clusters; one click reveals every member
- Device Focus Mode — isolate any single host and see only its sub-graph, connections, and external destinations
- Intelligent position memory — graph layout persists across data refreshes; nodes never randomly reshuffle
- Network Path Strip — visual hop-by-hop path: Internet → Gateway → Device → External Destinations, with live favicon resolution for domains
- Per-node risk ring: colour-coded threat level overlaid directly on every node (green / amber / red)
- Deep search: instant client-side match across IP, hostname, MAC, historical IPs, and passive DNS — supplemented by server-side search for clustered or unseen nodes
- Node type filters: All, Internal, External, Threats, High Traffic — each with live counts and animated transitions
- Zoom-adaptive layout: auto-scales to 0.3×–8× depending on network density
- Favicon intelligence — automatically resolves and displays brand icons for known external domains
- Dynamic node sizing: node radius scales with connection volume — busy hosts visually stand out
- Physics engine: D3 force simulation with charge repulsion (internal −1200 / external −600), link distance by connection weight, collision avoidance, and 0.04 alpha decay for stable settling
- Gateway-first layout: routers, gateways, firewalls, and switches anchor the internal cluster and sort to the centre

---

## 5. Asset Intelligence

**A living, enriched inventory of every device on your network — not just what it is, but what it's doing.**

- Auto-discovered asset registry: IP, MAC, hostname, vendor, OS fingerprint, device role, and criticality score for every host
- Hybrid Asset Model: tracks historical IPs per device — a laptop that changed IPs is still one asset, not two
- OS fingerprinting via JA3 TLS fingerprints — detects OS without agents
- IPAM subnet integration: visualise IP usage, free addresses, and per-subnet risk at a glance
- Subnet heat map: interactive cards showing CIDR, interface, usage ratio, and free capacity — click to filter instantly
- Asset type distribution dashboard: conic-gradient donut chart + breakdown across Workstations, IoT, Servers, Networking gear
- Inline asset naming: analysts rename any device without leaving the page — changes propagate across the platform
- Trust system: mark devices as Trusted to suppress noise; trust status automatically clears threat flags
- Advanced filtering: device type, subnet, last-seen (24h toggle), and full-text search across all fields including historical IPs
- Role classification: Server, Gateway, Workstation, IoT, Database — each with colour-coded role badges
- Criticality scoring: 0–100 risk score with visual progress bar and threshold-based colour coding
- Connection and alert counters: 24-hour connection count and alert count per asset, displayed inline in the inventory grid
- DeviceScope integration: click any asset row to open the full per-device intelligence panel

---

## 6. ThreatStream Live

**A real-time feed of every security event on your network — no delay, no polling, no missed detections.**

- Sub-second event delivery via persistent WebSocket connection — no page refresh required
- High-volume batching engine: processes thousands of events per second using out-of-zone batch flushing every 300 ms
- Unified event stream: Agent-Z network events, Agent-S threat alerts, and system events in a single chronological feed
- Per-event detail: source IP, destination IP, protocol, port, action, severity, threat score, and tags
- Auto-scroll with smart pause: stream auto-scrolls to newest events; pauses automatically when analyst scrolls up to investigate
- Event type badges: colour-coded by source (Agent-Z / Agent-S) for instant visual triage
- Live event counter: running total of events in session

---

## 7. Detection Logs

**Every detection, every alert, every network event — searchable, filterable, and ready for investigation.**

- Unified log view combining real-time WebSocket events with historical ClickHouse query results
- Time range selector: Last Hour, Last 6 Hours, 1 Day, 7 Days — all resolved server-side for accuracy
- Dual-source design: real-time events prepend seamlessly to historical records without duplicates
- Advanced filters: source IP, destination IP, protocol, action (ALLOW / BLOCK / ALERT), severity, sensor
- Smart deduplication: rapid-fire identical events are merged and counted rather than flooding the view
- Severity classification: Critical / High / Medium / Low with colour-coded row styling
- Per-sensor scoping: analysts see only the data their JWT grants access to — hardware-level isolation
- Export-ready structure: every log row carries a full event payload for downstream SIEM or ticketing

---

## 8. Agent-Z — Network Behaviour Engine

**Passive, always-on network behaviour analysis. Agent-Z sees everything that flows across your wire.**

- Deep protocol analysis: HTTP, DNS, TLS, SSH, SMB, FTP, RDP, and 50+ application protocols parsed natively
- Passive fingerprinting: OS, application, and device type identified from traffic patterns — no endpoint agent required
- Connection state tracking: every TCP/UDP session tracked with full metadata (duration, bytes, packets, state)
- DNS intelligence: full query/response logging, NXDOMAIN tracking, DGA detection
- TLS certificate inspection: issuer, subject, validity, JA3/JA3S fingerprints logged per session
- File extraction markers: identifies file transfers in-stream for forensic follow-up
- Lateral movement detection: internal east-west traffic profiled and anomaly-scored
- Passive DNS database: builds per-asset domain contact history over time
- Zero-touch deployment: network tap or SPAN port — no endpoint agents, no firewall changes
- Linux endpoint telemetry: auditd integration captures process execution, file writes, outbound connections, and privilege escalation on managed Linux hosts

---

## 9. Agent-S — Threat Signature Engine

**Real-time threat signature matching against the world's largest open ruleset — with zero false-positive noise.**

- Multi-thousand rule library covering CVSS Critical and High CVEs, malware C2 patterns, exploit kits, and reconnaissance techniques
- Custom rule authoring: analysts write platform-native detection rules with full field access (18 field types covering network events + Linux endpoint auditd)
- 5 matching strategies per rule: exact match, substring contains, prefix, suffix, and regex
- SigmaHQ community rules sync: pull the latest SigmaHQ detection library on demand — new rules hot-loaded with no service restart
- AI-assisted suppression: the platform automatically identifies and silences confirmed false positives
- Per-rule hit counters: see exactly how many times each rule has fired across the fleet
- MITRE ATT&CK tagging: community rules carry tactic and technique tags — filter rules by attack category or severity
- Action enforcement: ALLOW, BLOCK, ALERT, and DROP actions per rule — inline policy enforcement
- Rule enable / disable: pause a rule without deleting it — configuration preserved for reinstatement
- Hot reload: rule changes propagate to the detection engine in seconds without restarting any service

---

## 10. PacketVault — Full-Fidelity Packet Forensics

**Every packet, preserved. Every session, replayable. Evidence that holds up.**

- Full packet capture at wire speed — every byte of every session stored with nanosecond timestamps
- Per-session PCAP download: one click exports any session as a standard `.pcap` file for Wireshark analysis
- Session search: query by IP, port, protocol, time range, or payload content
- Integrated session viewer: inspect session metadata — duration, bytes transferred, protocol, geo-location — without downloading
- Per-device session history: DeviceScope shows the last 10 PCAP sessions for any selected host
- Chain-of-custody metadata: every capture record includes sensor ID, capture interface, and integrity hash
- Retention policy management: configurable per-tenant retention windows to meet compliance requirements
- Zero-gap capture guarantee: capture pipeline runs independently of detection — alerts never cause missed packets

---

## 11. AI Threat Intelligence

**Not just detection — prediction. The platform learns your network and anticipates what happens next.**

- Threat prediction engine: ML model scores each known threat pattern with a probability (0–100%) and trend direction (rising / stable / falling)
- Attack type forecasting: predicts likelihood of ransomware, lateral movement, data exfiltration, and C2 activity based on observed network behaviour
- Historical prediction tracking: every prediction archived with timestamp — see when the model saw it coming
- AI-driven auto-suppression: platform automatically generates suppression rules for confirmed false positives, validated by the analyst before activation
- AI analysis reports: natural-language summaries of detected anomalies with recommended actions
- Suppression lifecycle management: activate, deactivate, or permanently delete suppressions — full audit trail per entry
- Suppress by source IP, destination IP, or signature ID — surgical noise reduction without blind spots
- 15-second auto-refresh: threat intelligence dashboard stays current without manual reload

---

## 12. ARIA AI Analyst Console

**Your always-on AI threat analyst. Surfaces what matters, explains why it matters.**

- AI analyses viewer: browse every AI-generated threat analysis in chronological order — expandable detail panels with severity, source/destination flow, and natural-language analysis text
- Suppression management: review active AI suppression rules, deactivate or delete them individually
- Threat prediction tracker: monitor active and historical ML predictions per attack type, with expandable historical trend view and probability bars
- 15-second background refresh: console stays current without manual reload
- One-click navigation to full AI Security Report from the ARIA console
- Suppress-type labelling: rules classified as By Source IP, By Destination IP, or By Signature ID

---

## 13. ARIA AI Security Reports

**Boardroom-ready reports. AI-authored. Data-verified. Minutes to generate.**

- On-demand report generation for 24h, 7d, or 30d reporting periods
- Executive summary: 3-4 sentence CISO-level narrative written by ARIA from verified live platform data
- Threat landscape overview: 2-paragraph narrative describing observed attack patterns and predicted risks
- AI threat analyses section: all AI-generated anomaly analyses for the period, with severity and flow metadata
- MITRE ATT&CK mapping: ARIA automatically maps each analysis to the relevant ATT&CK v14 tactics and technique IDs
- Predictive threat intelligence section: probability-scored attack type forecasts with rising / stable / falling trend indicators
- Autonomous suppression log: record of every AI suppression decision in the report period
- Recommendations: 6 prioritised operational recommendations generated from actual observed threats
- KPI metrics panel: False-Positive Suppression Rate, AI Detection Coverage, Average AI Confidence, Active Suppression Rate, Critical Alert Rate, Agent-Z/S event ratio — all computed from live data
- System health appendix: current platform service status and event throughput
- Custom report builder: drag-and-drop section reordering, per-section enable/disable toggles
- PDF export: browser-native print-to-PDF with print-optimised stylesheet
- Unique report ID: every generated report carries a unique NDR-YYYYMMDD-HHMM-XXXX identifier for audit trail
- Auto-regenerate: changing the reporting period on a generated report automatically refreshes all data and narratives

---

## 14. DeviceScope — Per-Device Intelligence

**Click any device. Know everything about it in seconds.**

- Instant device panel: one click on any asset opens a full intelligence drawer — no navigation required
- Risk gauge: 0–100 risk score calculated from criticality, threat status, and connection volume — displayed as an animated arc
- Traffic activity sparkline: 14-bar activity visualisation seeded per device for instant pattern recognition
- Top connections: ranked peer list with relative connection volume bars — see who this device talks to most
- Protocol breakdown: top 6 protocols observed for this device
- Connected websites: automatic favicon resolution for every external domain this device contacted
- Passive DNS history: all domains ever contacted by this device, with resolved IP list for domain-type nodes
- Connection detail tab: full peer list with protocol tags and connection counts
- Alert history tab: all threat alerts involving this device, sourced in real time
- PCAP session tab: last 10 packet capture sessions — downloadable with one click (via PacketVault)
- Inline device naming: rename any device directly from the panel
- Focus Mode: collapse the full network map down to just this device and its connections
- Copy-to-clipboard: one-click copy for IP addresses and identifiers

---

## 15. Digital Evidence & Forensic Chain of Custody

**Tamper-evident evidence. Legally defensible. Ready for court or compliance review.**

- Tamper-evident evidence bundles: each bundle cryptographically hashed (SHA-256) — integrity verifiable at any time
- Corroboration status: every bundle labelled as Agent-Z-only, Agent-S-only, or Z+S corroborated — immediately visible to the analyst
- ARIA AI verdict: run AI investigation on any bundle to receive a TRUE_POSITIVE / FALSE_POSITIVE / SUSPICIOUS verdict with confidence score
- Legal hold: mark any bundle as legally held with a reason — prevents deletion until hold is cleared
- Timeline view: chronological replay of all events associated with a community ID
- Annotation system: add investigation notes and tags directly to evidence bundles — all annotations persisted server-side
- Bundle download: download the complete evidence package for offline analysis
- IP-grouped view: bundles organised by source→destination IP pair for rapid attacker-path reconstruction
- Auto-open linking: navigate from SOAR cases or alert console directly to the matching evidence bundle
- Chain-of-custody metadata: sensor ID, capture interface, corroboration status, and creation timestamp on every bundle

---

## 16. Global Threat Map

**See where attacks are coming from — in real time, on a live world map.**

- Live animated world map (D3.js + TopoJSON, Natural Earth projection) showing attack arc paths from origin countries to your protected network
- Real-time animated attack arcs: each arc draws itself with a 1.4-second animated stroke per country
- Particle effects: glowing particles travel continuously along each arc at speeds proportional to attack volume
- Source country dots: pulsing rings and glow effects scale with attack count — high-volume origins are visually dominant
- Clickable country cards: select any source country to see a breakdown of attack types (port-scan, DNS beaconing, lateral movement, etc.) and total hit count
- Total attack counter: platform-wide inbound threat volume displayed in real time
- Country label pills: semi-transparent labels with monospaced font overlaid directly on the map for instant identification
- Responsive canvas: map auto-redraws on viewport resize to fill available space

---

## 17. SOAR — Security Orchestration, Automation & Response

**From detection to response in seconds — not hours.**

- 8-stage case workflow: New → Assigned → In Progress → Pending → Under Review → Resolved → Closed → False Positive
- Case lifecycle management: create, assign, comment, escalate, resolve, and close incidents from a single console
- Case statistics: active cases, in-progress count, cases resolved today, average resolution time in hours — all computed live
- Assignee management: inline assignee edit per case — auto-assigns current analyst when marking Assigned
- Case comments and notes: threaded comment log per case, including session notes and PCAP analysis annotations
- Incident report generation: one-click PDF-ready incident report with case number, resolution, analyst, evidence count, and tags
- One-click case creation from alerts: full alert metadata (IPs, tags, Sigma hits, community ID) pre-filled
- Visual playbook builder: condition-action chains triggered by any platform detection — define field, operator, threshold, and action type
- 20 supported integration types:
  - **Notification:** Slack, Microsoft Teams, Discord, Webhook, PagerDuty, Telegram, Email (SMTP)
  - **Firewall:** pfSense, FortiGate, PAN-OS, OPNsense
  - **Network switch:** UniFi, Cisco SNMP, Aruba CX, Generic SNMP
  - **Cloud:** AWS Security Group, Azure NSG, GCP VPC Firewall
- Live integration testing: test any integration configuration with one click before enabling
- IP blocking: manual or automated block by source IP and optional port — enforcement via TCP RST, host firewall rules, or both — configurable duration (hours)
- Device isolation: quarantine any device from the network using ARP spoofing (instant, agent-side) or physical enforcement via UniFi, Cisco IOS VLAN quarantine, Aruba CX, generic SNMP, or cloud security groups (AWS/Azure/GCP)
- Animated isolation progress: step-by-step isolation wizard with live status for each enforcement stage
- Block management tab: view and revoke all active IP blocks per sensor
- Isolation management tab: view all active device isolations with enforcement method and restoration option
- In-app PCAP viewer: binary PCAP parser built into the case console — decode TCP/HTTP/TLS/DNS/ICMP/ARP/UDP packets without leaving the browser
- PCAP analysis panel: traffic timeline chart, per-protocol packet/byte breakdown, connection list, HTTP request log, DNS query/response table, TLS SNI tracking
- PCAP download: one-click export of any session PCAP from inside a case
- Evidence overlay: open the evidence timeline for a case in an inline panel without navigating away
- Per-tenant playbook isolation: in multi-tenant deployments, no playbook can cross tenant boundaries
- Deduplication engine: identical simultaneous alerts trigger one playbook run, not hundreds
- Playbook audit log: every automated action recorded with timestamp, triggering event, and outcome
- Activity log tab: full history of playbook run events across all cases
- False positive resolution: closing a case as False Positive can optionally add the source IP to the threat intelligence watchlist

---

## 18. Platform Health Observatory

**Always know if your sensors and services are working — before your analysts notice they aren't.**

- 7-service health dashboard: Agent-Z IDS, Agent-S EVE, Telemetry Pipeline, PCAP Engine, Kafka Broker, NDR Engine, ClickHouse DB — each with a colour-coded status badge (Healthy / Down / Unknown)
- Sensor heartbeat monitor: a sensor is considered online only if its last heartbeat was within the past 6 minutes — stale sensors are marked down automatically
- Status rollup: service status rolls up across all online sensors — if any online sensor reports a service running, the platform shows it as Healthy
- Platform metrics: total events processed, total correlation hits, events per hour, active PCAP sessions, sigma rules loaded
- Active/online sensor counter: at-a-glance `N/M online` display for the tenant's sensor fleet
- 10-second auto-refresh: health dashboard updates without analyst intervention
- Per-service status indicators: animated pulse for Unknown, static red for Down, glowing green for Healthy

---

## 19. Rules Engine

**Write once. Detect everywhere. Rules that scale from one sensor to ten thousand.**

- Platform-native rule language: full access to all network and endpoint fields — no vendor lock-in, no proprietary syntax
- 18 field types: network (event_type, protocol, source/dest IP, connection state, application protocol, alert severity, alert signature, alert category, log source) + Linux endpoint (process image, command line, parent process, target filename, destination IP/port, user, auditd record type)
- Real-time rule validation: syntax errors caught before deployment
- Per-rule action assignment: ALERT, BLOCK, ALLOW, or DROP
- 5 matching operators: Equals, Contains, Starts With, Ends With, Regex
- MITRE ATT&CK category tagging: tag rules by attack phase for framework-aligned coverage reporting
- SigmaHQ community rules: one-click pull of the entire SigmaHQ detection library — new rules hot-loaded with no restart
- Rule hit counters: see exactly how many times each rule has fired, and when
- Category filter chips: quickly filter the rule library by attack.lateral-movement, attack.persistence, attack.exfiltration, and more
- Severity filter: filter rules by Critical / High / Medium / Low in one click
- Enable / disable without deletion: pause a rule during maintenance windows without losing its configuration
- Hot reload: changes propagate to all detection engines in seconds — no service downtime

---

## 20. Sensor Deployment & Fleet Control

**Sensors deployed in minutes. Managed from the console. Controlled from anywhere.**

- One-line sensor install: generate a signed install command that registers the sensor, configures services, and connects to the platform automatically
- Sensor key generation: create named sensor keys per tenant — each key scoped to one sensor deployment
- Copy key + command: one-click copy for both the raw API key and the full `curl | bash` install command
- Custom server URL: override the auto-detected cloud URL for air-gapped or behind-NAT deployments
- External sensor management: view all registered sensors with hostname, OS, network interface, and last-seen timestamp
- Per-sensor service status: real-time Agent-Z, Agent-S, and Vector pipeline status per sensor card
- Online / offline detection: sensors not seen within 2 minutes shown as offline with last-seen timestamp
- Remote sensor control: start, stop, and restart Agent-Z, Agent-S, and Vector pipeline on any external sensor from the console — command queued and delivered via secure agent channel
- Local sensor tab: local sensor status, network interface selection, and one-click start/stop for default-tenant deployments
- Real-time status via WebSocket: local sensor service status updates arrive via WebSocket push — no polling required
- 30-second auto-refresh for external sensor list

---

## 21. Admin Command Center

**Platform-wide visibility and control. One console for everything.**

- Live super-admin dashboard: real-time CPU and memory utilisation area charts updated every 3 seconds
- Tenant user count bar chart: animated horizontal bar showing which tenants have the most users — refreshes on data change
- User role distribution donut: breakdown across Platform Admin, Tenant Admin, Analyst, Viewer, Other
- Engine status donut: running vs. offline detection engine node count at a glance
- Live system clock: UTC time and date displayed continuously — current to the second
- Platform-level admin access: create, edit, activate, and deactivate tenants from a single interface
- User management: create, search, and manage users across all tenants; assign roles; reset credentials
- AI provider registry: add custom or hosted AI providers (OpenAI, Anthropic, or any OpenAI-compatible endpoint) — use-case routing for ARIA chat vs. threat analysis

---

## 22. License & Tenant Lifecycle Management

**Provision a new customer in minutes. Control every feature, seat, and sensor.**

- Tenant creation with slug auto-generation: enter a tenant name, ID auto-slugifies — collision detection prevents duplicates
- Per-tenant feature flags: enable or disable NDR, AI, and SOAR features independently per tenant
- Per-tenant AI toggle: enable or disable AI analysis features per tenant without affecting other tenants
- Tenant activate / deactivate: suspend a tenant account with one click — data preserved, access revoked
- License generation: produce signed JWT license tokens scoped to tenant ID, feature set, expiry, and maximum sensor count
- License management: view all issued licenses per tenant with issue date, expiry, and feature list
- Install package builder: generate a complete, copy-ready install package with license token, public verification key, admin credentials, and `bash <(curl ...)` install command
- Admin credential pre-provisioning: embed tenant admin username in the install package — forces secure password entry at install time
- License revocation: delete a license from the console to prevent future activations

---

## 23. Detection Engine Cluster

**Elastic detection at any scale. Kafka-backed, zero-downtime horizontal scaling.**

- Kafka-backed event bus: all sensor events flow through Kafka topics partitioned across engine workers — no single point of failure
- Kafka health monitor: per-partition consumer status, offset tracking, and consumer lag — visible in real time with 10-second refresh
- Horizontal scale-up: add detection engine worker nodes from the console with one click — load distributes automatically via Kafka partition assignment
- Controlled scale-down: gracefully stop a specific engine node with a two-step confirmation — in-flight events complete before shutdown
- SigmaHQ community rules sync: pull the latest SigmaHQ community detection library on demand — sync runs in background, rules hot-loaded
- Engine status list: all worker nodes with current status, last seen timestamp, and partition assignment
- Engine refresh: re-query all engine statuses on demand

---

## 24. Platform Communications — Announcements

**Push messages to every analyst, every tenant admin, or a specific customer — on schedule.**

- 4 announcement types: Information, Maintenance, Platform Update, Critical
- 3 audience targets: All Users, Tenant Admins, or a specific Tenant
- Scheduled announcements: set a start time and end time — announcement activates and deactivates automatically
- Half-hour time slot picker with past-time filtering: no invalid schedules possible
- Activate / deactivate toggle: enable or disable an announcement without deleting it
- Search and filter: find announcements by title, message text, type, or audience
- Create and delete with confirmation: guard against accidental removal of active notices

---

## 25. Trusted Domain & Cloud Allowlists

**Fine-tune your detection baseline. Silence noise without creating blind spots.**

- Trusted domain registry: mark domains as trusted (dns_beacon category or custom) to suppress DNS beaconing alerts for known infrastructure
- Scope options: global trust (suppresses for all tenants) or tenant-scoped trust (suppresses only for the requesting tenant)
- Category tagging: classify trusted domains by alert category (dns_beacon, etc.) for future filtering
- AI-assisted suggestions: ARIA analyses your network's DNS history and recommends domains it believes are safe — approve or dismiss each suggestion individually
- Trusted cloud allowlist: define trusted cloud provider keywords and domains (e.g., `AWS`, `MICROSOFT`) — traffic matching these patterns is whitelisted for volume anomaly detection
- Organisation suggestion review: the platform surfaces organisations detected in your traffic as trust candidates — one-click approve or reject
- Tenant-level domain management: tenant admins manage their own trusted domain list independently of other tenants
- Global vs. tenant visibility: tenant admins see both their own and globally trusted domains, clearly labelled

---

## 26. Session Security & Remote Access Control

**Know who's logged in. Force them out if you need to.**

- Active session monitor: view all currently logged-in users per tenant with device type, source IP, and login timestamp
- Per-user session grouping: sessions grouped by username — see all active devices for each user at a glance
- Device-level force logout: sign out a specific device (by username + IP + device) without affecting other sessions for that user
- User-level force logout: sign out a user from all devices simultaneously with a single confirmed action
- Session count per device: multiple tabs or tokens from the same device/IP shown as a session count
- Session list auto-refresh: reload sessions on demand to see who connected or disconnected

---

## 27. Platform Infrastructure

**Performance-first architecture built to handle enterprise-scale traffic without compromise.**

- Rust-powered detection engine: sub-millisecond packet processing at multi-gigabit line rates
- ClickHouse time-series backend: billions of events queryable in milliseconds
- WebSocket real-time bus: persistent connections with intelligent backpressure and 300ms high-volume batching (outside Angular zone for zero UI blocking)
- Sensor fleet management: deploy lightweight sensors anywhere — data centre, branch office, cloud VPC
- OUI vendor lookup: hardware vendor identified from MAC address for every discovered device
- Force-logout security: compromised sessions remotely invalidated across all active connections
- API-first design: every platform capability exposed via authenticated REST API
- JWT-scoped data isolation: every API call, WebSocket event, and UI element is tenant-bound at the token level — hardware-level sensor isolation
- SMTP email alerts: configurable global SMTP relay for email-based alert delivery and notification routing
- Platform telemetry: real-time CPU and memory metrics exported every 5 seconds for admin dashboards

---

## 28. Multi-Tenant MSSP Architecture

**Built for service providers from day one. Not bolted on later.**

- Hardware-level sensor isolation: each tenant's traffic never touches another tenant's pipeline
- JWT-scoped data access: every API call, WebSocket event, and UI element is tenant-bound at the token level
- Per-tenant sensor management: add, remove, and configure sensors without cross-tenant impact
- Unified MSSP console: manage all tenants from a single super-admin interface
- Per-tenant rule sets: detection logic is fully isolated — one client's suppression never silences another's alert
- Per-tenant SOAR: playbooks, suppressions, and response actions are tenant-local
- Role hierarchy: Super Admin → Tenant Admin → Analyst — each with scoped permissions
- Per-tenant AI controls: enable or disable AI analysis features independently per client
- White-label ready: platform UI, terminology, and branding fully customisable per tenant

---

*Platform version: v1.0.10 — Powered by PromaSecure*
