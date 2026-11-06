import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn
import os

def create_element(name):
    return OxmlElement(name)

def set_cell_background(cell, fill_hex):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._element.get_or_add_tcPr()
    tcMar = parse_xml(f'''
        <w:tcMar {nsdecls("w")}>
            <w:top w:w="{top}" w:type="dxa"/>
            <w:bottom w:w="{bottom}" w:type="dxa"/>
            <w:left w:w="{left}" w:type="dxa"/>
            <w:right w:w="{right}" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)

def set_cell_borders(cell, top="D1D5DB", bottom="D1D5DB", left=None, right=None):
    tcPr = cell._element.get_or_add_tcPr()
    borders_xml = f'<w:tcBorders {nsdecls("w")}>'
    borders_xml += f'<w:top w:val="single" w:sz="4" w:space="0" w:color="{top}"/>' if top else '<w:top w:val="none"/>'
    borders_xml += f'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="{bottom}"/>' if bottom else '<w:bottom w:val="none"/>'
    borders_xml += f'<w:left w:val="single" w:sz="4" w:space="0" w:color="{left}"/>' if left else '<w:left w:val="none"/>'
    borders_xml += f'<w:right w:val="single" w:sz="4" w:space="0" w:color="{right}"/>' if right else '<w:right w:val="none"/>'
    borders_xml += '</w:tcBorders>'
    tcPr.append(parse_xml(borders_xml))

def build_technical_doc(output_path):
    doc = docx.Document()

    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    COLOR_PRIMARY = RGBColor(15, 23, 42)      # Deep Navy #0F172A
    COLOR_SECONDARY = RGBColor(14, 165, 233)  # Cyber Blue #0EA5E9
    COLOR_DARK = RGBColor(30, 41, 59)         # Slate Dark #1E293B
    COLOR_MUTED = RGBColor(100, 116, 139)     # Slate Gray #64748B

    def add_title(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(26)
        run.font.bold = True
        run.font.color.rgb = COLOR_PRIMARY
        return p

    def add_subtitle(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(14)
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(13)
        run.font.color.rgb = COLOR_SECONDARY
        return p

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(16)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(15)
        run.font.bold = True
        run.font.color.rgb = COLOR_PRIMARY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(11)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(12)
        run.font.bold = True
        run.font.color.rgb = COLOR_SECONDARY
        return p

    def add_body(text, bold_prefix=None):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.font.name = "Calibri"
            r_pre.font.size = Pt(10)
            r_pre.font.bold = True
            r_pre.font.color.rgb = COLOR_DARK
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(10)
        run.font.color.rgb = COLOR_DARK
        return p

    def add_bullet(text, bold_prefix=None):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.font.name = "Calibri"
            r_pre.font.size = Pt(10)
            r_pre.font.bold = True
            r_pre.font.color.rgb = COLOR_DARK
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(10)
        run.font.color.rgb = COLOR_DARK
        return p

    def add_styled_table(headers, data, col_widths=None):
        tbl = doc.add_table(rows=len(data) + 1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False

        # Header Row
        hdr_row = tbl.rows[0]
        tbl._tbl.tblPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        for idx, title in enumerate(headers):
            cell = hdr_row.cells[idx]
            if col_widths and idx < len(col_widths):
                cell.width = Inches(col_widths[idx])
            set_cell_background(cell, "0F172A")
            set_cell_margins(cell, 120, 120, 140, 140)
            set_cell_borders(cell, "0F172A", "0F172A")
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(title)
            run.font.name = "Calibri"
            run.font.size = Pt(9.5)
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)

        # Data Rows
        for r_idx, row_data in enumerate(data):
            row = tbl.rows[r_idx + 1]
            bg_color = "F8FAFC" if r_idx % 2 == 1 else "FFFFFF"
            for c_idx, val in enumerate(row_data):
                cell = row.cells[c_idx]
                if col_widths and c_idx < len(col_widths):
                    cell.width = Inches(col_widths[c_idx])
                set_cell_background(cell, bg_color)
                set_cell_margins(cell, 90, 90, 120, 120)
                set_cell_borders(cell, "E2E8F0", "CBD5E1")
                p = cell.paragraphs[0]
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                p.paragraph_format.space_before = Pt(0)
                p.paragraph_format.space_after = Pt(0)
                run = p.add_run(str(val))
                run.font.name = "Calibri"
                run.font.size = Pt(9)
                run.font.color.rgb = COLOR_DARK

        p_after = doc.add_paragraph()
        p_after.paragraph_format.space_before = Pt(4)
        p_after.paragraph_format.space_after = Pt(6)

    # ---------------- COVER / HEADER ----------------
    add_title("ProVigil")
    add_subtitle("Technical Documentation — Part 1 (Unified Modern Agent Edition)\nModule 1: Platform Architecture\nModule 2: Agent Management\nModule 3: Endpoint Posture: Inventory, FIM, SCA & Compliance\nModule 4: Threat Detection: Rules, Decoders, Sigma, MITRE ATT&CK & Alert Pipeline\nModule 5: Vulnerability Detection & CVE Management\nModule 6: Active Response & Incident Remediation\nModule 7: Syslog Ingestion & Network Appliance Monitoring")

    meta_headers = ["Item", "Value"]
    meta_data = [
        ["Product", "ProVigil SIEM / EDR (Multi-Tenant, Modern Pure-Rust Agent Edition)"],
        ["Audience", "Security Engineers, Platform Architects & SOC Analysts"],
        ["Prepared by", "Jithin"],
        ["Date", "5 November 2026"],
        ["Code references", "File names relative to backend-rust/ (server) and ndr-ui/ (console)"]
    ]
    add_styled_table(meta_headers, meta_data, [2.0, 5.0])

    # ---------------- EXECUTIVE MATRIX TABLE ----------------
    add_h1("Executive Architecture Matrix: Modules 1–7")
    matrix_headers = ["Module", "Title", "Core Architecture & Capabilities"]
    matrix_data = [
        ["1", "Platform Architecture", "Agent gateway (gRPC/TLS & HTTPS), microservices, analysis engine, ProVigil DB, modules daemon, ClickHouse + SQLite storage, multi-tenant isolation, write-ahead platform stream with no-loss delivery."],
        ["2", "Agent Management", "One-command deployment, self-enrollment over TLS with a private CA (tenant key), per-agent cryptographic keys, groups and central configuration, remote restart and upgrade with automatic rollback, deactivation and safe removal."],
        ["3", "Endpoint Posture: Inventory, FIM, SCA & Compliance", "Hardware/OS/ports/processes/software inventory (incl. Python, npm, Store apps), file and registry integrity monitoring with who-data, 19 ProVigil configuration policies (3,205 checks) for Windows 10/11, Server 2012–2025, IIS, SQL Server, MySQL, PostgreSQL and Apache; rootcheck; scoring for PCI DSS, HIPAA, NIST 800-53, ISO 27001, GDPR and SOC 2."],
        ["4", "Threat Detection: Rules, Decoders, Sigma, MITRE ATT&CK & Alert Pipeline", "Pre-decoding, 8,400+ detection rules, Sigma rule engine, MITRE ATT&CK mapping, alert levels 0–15, WebSocket push bus."],
        ["5", "Vulnerability Detection & CVE Management", "NVD and OSV feeds, package matching across Windows, Python and npm, CVSS scoring, per-agent and fleet views, self-healing re-scans, customizable Excel reports."],
        ["6", "Active Response & Incident Remediation", "Firewall blocks (netsh / iptables / null route) with timed undo that survives restarts, process termination, host isolation, file quarantine and restore, YARA scans, live response, tamper protection, repeat-offender escalation."],
        ["7", "Syslog Ingestion & Network Appliance Monitoring", "Listeners on UDP 514, TCP 601 and TLS 6514, per-tenant mutual TLS with internal CA certificates, IP-based tenant routing, GeoIP attack mapping."]
    ]
    add_styled_table(matrix_headers, matrix_data, [0.8, 2.2, 4.0])

    # ---------------- MODULE 1 ----------------
    add_h1("Module 1 — Platform Architecture")
    add_h2("1.1 What ProVigil is")
    add_body("ProVigil is an enterprise multi-tenant SIEM and EDR platform. Endpoints run the modern ProVigil agent (provigil-agent), engineered in 100% clean-room Rust with zero legacy C or GPL dependencies. The ProVigil manager daemons receive real-time telemetry over an encrypted gRPC/TLS and HTTPS agent gateway, decode high-velocity log streams, evaluate correlation rules, and maintain live endpoint state. siem-api serves the web console and unified APIs, enforcing strict tenant isolation across ClickHouse (event telemetry, alerts, cases, audit logs) and SQLite (endpoint state databases).")

    add_h2("1.2 Components")
    comp_headers = ["Component", "Role", "Code", "Port"]
    comp_data = [
        ["ProVigil Console", "Enterprise Angular 21 web console for analysts, tenant admins and platform operators.", "ndr-ui/", "4200 (dev server)"],
        ["Auth Service", "Identity provider: JWT session management, RBAC, tenant entitlement checks.", "Shared service", "3011"],
        ["siem-api", "Core API gateway, WebSocket bus, event pipeline, tenant boundary guard, supervisor.", "crates/siem-api", "8088 (REST/WS)"],
        ["ProVigil Manager Daemons", "Eight background micro-daemons executing analysis, agent connections, DB sync, and feeds.", "data/manager/bin/", "1514/TCP (Agent Gateway)"],
        ["ProVigil Agent (Windows)", "Modern pure-Rust service (ProVigilSvc): logs, FIM with who-data, inventory, 19 SCA policies, active response.", "crates/provigil-agent", "Outbound to 1514/8088"],
        ["ProVigil Agent (Linux)", "Pure-Rust Linux endpoint agent with eBPF/auditd kernel hooks and systemd integration.", "crates/siem-agent-linux", "Outbound to 1514/8088"],
        ["ClickHouse", "Columnar big-data analytics engine: telemetry, alerts, vulnerabilities, audit trails.", "—", "8123 (HTTP)"],
        ["Syslog Ingestion Gateway", "RFC-compliant receiver for firewalls, switches and appliances with per-tenant mTLS.", "siem-api/src/syslog.rs, syslog_tenancy.rs", "514/UDP, 601/TCP, 6514/TLS"]
    ]
    add_styled_table(comp_headers, comp_data, [1.8, 2.5, 1.8, 0.9])

    add_h2("1.3 The ProVigil Manager Daemons")
    add_body("siem-api supervises and starts the eight core manager daemons from data/manager/bin, in strict topological order, auto-recovering any stopped daemon in under 5 seconds:")
    daemon_headers = ["Program", "What it does", "Crate / Origin"]
    daemon_data = [
        ["provigil-db", "ProVigil DB: Multi-threaded SQLite database manager handling agent databases and MITRE catalogue over local sockets.", "siem-wdb"],
        ["provigil-analysisd", "High-throughput detection engine: runs pre-decoders, decoders, and 8,400+ rules; generates alerts.", "siem-analysisd"],
        ["provigil-remoted", "Agent connection gateway: sustains 50,000+ persistent agent links encrypted with per-agent AES-256 keys.", "siem-remoted"],
        ["provigil-modulesd", "Manager modules coordinator: drives vulnerability scanning, package sync, agent upgrades, and SCA.", "siem-modulesd, siem-vulnerability-scanner"],
        ["provigil-monitord", "Agent connectivity monitor, keepalive watchdog, and log rotation manager.", "siem-monitord"],
        ["provigil-maild, provigil-integratord, provigil-csyslogd", "Manager alert dispatchers to external SMTP, Webhooks (Slack/Jira), and upstream syslog relays.", "siem-maild, siem-integratord, siem-csyslogd"]
    ]
    add_styled_table(daemon_headers, daemon_data, [2.0, 3.5, 1.5])

    add_h2("1.4 How a Console Request is Handled")
    add_bullet("The analyst browser navigates to the Angular console. The proxy (ndr-ui/proxy.conf.json) forwards /api/auth to Auth Service (:3011) and /api, /downloads to siem-api (:8088).")
    add_bullet("siem-api's tenancy middleware (siem-api/src/tenancy.rs) validates the JWT session token, resolving tenant_id, role permissions, and allowed page scopes.")
    add_bullet("Page-level authorization checks verify the caller's rights (e.g. siem-fim for FIM, siem-vulnerabilities for CVE audits); missing permissions return 403 Forbidden.")
    add_bullet("Every per-agent URI (/api/v1/agents/:id/...) enforces cryptographic tenant ownership; an agent belonging to another tenant returns 404 Not Found as if it did not exist.")
    add_bullet("The handler executes scoped strictly to the authenticated tenant, querying only ndr_<tenant> in ClickHouse or the tenant's agent databases in ProVigil DB.")

    add_h2("1.5 Write-Ahead Platform Stream with No-Loss Delivery")
    add_bullet("The ProVigil agent sends encrypted telemetry batches to provigil-remoted on 1514/TCP.")
    add_bullet("provigil-remoted delivers the batch to provigil-analysisd for real-time decoding, correlation, and rule evaluation.")
    add_bullet("analysisd writes events (E), alerts (A), and scanner results (V) across the write-ahead platform stream directly into siem-api.")
    add_bullet("Framing: [u32 length, little endian][1 byte kind: H=token, A=alert, E=event, V=vulnerability][binary payload].")
    add_bullet("No-Loss Guarantee: analysisd maintains a memory-backed ring buffer of up to 50,000 records. During database restarts or high load, stream writes pause and queue safely; siem-api acknowledges batches only after successful ClickHouse commit.")

    # ---------------- MODULE 2 ----------------
    add_h1("Module 2 — Agent Management")
    add_h2("2.1 What it does")
    add_body("Agent Management automates the entire lifecycle of the modern ProVigil agent fleet across Windows and Linux workstations, servers, and cloud instances. Features include one-command automated deployment, self-enrollment over TLS with a private CA, cryptographic per-agent keys, centralized group configurations, remote restarts, in-place upgrades with automatic failure rollback, and safe deactivation and removal.")

    add_h2("2.2 Pages")
    agent_pages_headers = ["Page", "URL", "Who", "Front-end files"]
    agent_pages_data = [
        ["Agent Deployment", "/tenant-admin/agent-deployment", "Tenant Admin", "src/pages/tenant-admin/agent-deployment/agent-deployment.ts, .html\nsrc/services/siem/agent-deploy.ts"],
        ["Agent Fleet & Host Detail", "/analyst/agents", "Analysts with Agents permission", "src/pages/analyst/agents/agents.ts, .html, .css\nsrc/services/siem/siem.service.ts"],
        ["ProVigil Manager Status", "/admin/siem-manager", "Platform Admin", "src/pages/admin/siem-manager/siem-manager.ts"]
    ]
    add_styled_table(agent_pages_headers, agent_pages_data, [1.8, 1.8, 1.4, 2.0])

    add_h2("2.3 Agent Lifecycle")
    add_bullet("1. One-Command Deployment: Tenant admins select target OS, hostname, and group. The console generates a single PowerShell or Bash command downloading provigil-agent.exe, installing ProVigilSvc, enabling Sysmon, and activating advanced audit policies.")
    add_bullet("2. Self-Enrollment Over TLS: On first boot, the agent connects to POST /api/v1/agents/enroll authenticated with the tenant enrollment key (X-Tenant-Key). siem-api verifies the tenant, issues a permanent unique agent ID, encrypts the agent's AES-256 key into ClickHouse ndr.agent_keys, and registers the host in ProVigil DB (global.db).")
    add_bullet("3. Central Configuration & Groups: Agents belong to tenant groups (data/manager/etc/shared/<tenant>.<group>/agent.conf). remoted dynamically pushes merged configuration updates to agents on their next keepalive.")
    add_bullet("4. Remote Restarts & Health: Operators can restart agents remotely via the console (POST /api/v1/agents/:id/restart). Heartbeats arrive every 10 seconds; hosts missing keepalives for 60 seconds are flagged as Disconnected.")
    add_bullet("5. In-Place Upgrades with Auto-Rollback: Upgrades are orchestrated via POST /api/v1/agents/:id/upgrade. The agent stages the new binary, validates its cryptographic signature, and executes an atomic replacement. If the new service fails health checks within 60 seconds, it automatically rolls back to the previous binary.")
    add_bullet("6. Deactivation & Safe Removal: Deactivated agents are muted without data loss. Permanent removal deletes the agent SQLite file (queue/db/<id>.db), marks the registry key deleted to prevent ID collisions, and retains security alerts for regulatory compliance.")

    # ---------------- MODULE 3 ----------------
    add_h1("Module 3 — Endpoint Posture: Inventory, FIM, SCA & Compliance")
    add_h2("3.1 What it does")
    add_body("Endpoint Posture provides exhaustive visibility into host security hygiene and configuration compliance. It audits system hardware, OS builds, open ports, running processes, and installed software (including Windows Registry packages, Python pip libraries, global npm packages, and Windows Store apps). It enforces real-time File and Registry Integrity Monitoring (FIM) with Who-data user attribution, runs 19 ProVigil configuration policies comprising 3,205 CIS benchmark checks across Windows and server applications, executes rootcheck anomaly scans, and generates compliance scoring against PCI DSS, HIPAA, NIST 800-53, ISO 27001, GDPR, and SOC 2.")

    add_h2("3.2 Pages")
    posture_pages_headers = ["Page", "URL", "What it shows", "Front-end files"]
    posture_pages_data = [
        ["Agent Detail View", "/analyst/agents", "Interactive tabs for Hardware, Network, Software, FIM, SCA (3,205 checks), and Rootcheck", "src/pages/analyst/agents/agents.ts, .html"],
        ["File Integrity Monitoring", "/analyst/fim", "Fleet-wide monitored files, real-time modification feeds, Who-data attribution (User, PID, Process)", "src/pages/analyst/fim/fim.ts, .html, .css"],
        ["Compliance Audit", "/analyst/compliance", "Automated compliance posture scores across PCI DSS, HIPAA, NIST 800-53, ISO 27001, GDPR, SOC 2", "src/pages/analyst/compliance/compliance.ts, .html, .css"]
    ]
    add_styled_table(posture_pages_headers, posture_pages_data, [1.8, 1.8, 2.0, 1.4])

    add_h2("3.3 How it works")
    add_bullet("Multi-Ecosystem Software Inventory: syscollector audits native OS packages, Python pip installations, npm global modules, and Windows Store / Appx packages, synchronizing deltas into the agent's SQLite sys_* tables.")
    add_bullet("FIM with Who-Data: Monitors system directories and sensitive registry hives using native OS hooks. When a file is altered, the agent captures the cryptographic hash (SHA256), the modifying username, process name, and PID, streaming FIM alerts to ClickHouse.")
    add_bullet("19 ProVigil Configuration Policies (3,205 Checks): Evaluates endpoint configurations against tailored CIS policies for Windows 10/11, Windows Server 2012–2025, IIS, Microsoft SQL Server, MySQL, PostgreSQL, and Apache HTTP Server. Results land in SQLite sca_* tables and sync to ClickHouse siem_sca_checks.")
    add_bullet("Rootcheck Anomaly Engine: Scans for stealth rootkits, clandestine listening sockets, promiscuous network interfaces, and unlinked kernel drivers, populating findings in pm_event.")
    add_bullet("Enterprise Compliance Engine: Correlates SCA benchmark checks and real-time alerts against regulatory frameworks, generating auditable pass/fail scores for PCI DSS v4.0, HIPAA, NIST 800-53, ISO 27001, GDPR, and SOC 2.")

    # ---------------- MODULE 4 ----------------
    add_h1("Module 4 — Threat Detection: Rules, Decoders, Sigma, MITRE ATT&CK & Alert Pipeline")
    add_h2("4.1 What it does")
    add_body("The Threat Detection Engine processes incoming event streams in real time from endpoints, network appliances, and cloud services. It normalizes unstructured logs, evaluates them against pre-packaged XML detection rules (8,400+ rules across 160 threat categories) and community/custom Sigma rules, maps incidents against the MITRE ATT&CK enterprise matrix, and dispatches high-fidelity alerts (Levels 0–15) across a full-duplex WebSocket push bus to analyst SOC dashboards.")

    add_h2("4.2 Pages")
    det_pages_headers = ["Page", "URL", "What it shows", "Front-end files"]
    det_pages_data = [
        ["Alerts Stream", "/analyst/alerts", "Real-time alert feed, threat levels (0–15: Low to Critical), rule drilldown, MITRE tactic tags, raw log inspection", "src/pages/analyst/alerts/alerts.ts, .html, .css"],
        ["Rules & Decoders", "/analyst/rules, /analyst/siem-rules", "Repository of 8,400+ active XML/YAML rules, custom rule editor, syntax validator, and hot reload", "src/pages/analyst/rules/rules.ts, .html, .css"],
        ["MITRE ATT&CK Matrix", "/analyst/mitre", "Interactive matrix across all 14 enterprise tactics visualizing attack techniques, coverage density, and alerts", "src/pages/analyst/mitre/mitre.ts, .html, .css"],
        ["Logtest Sandbox", "/analyst/logtest", "Live testing console evaluating test logs through Phase 1 (pre-decoder), Phase 2 (decoder), Phase 3 (rule)", "src/pages/analyst/logtest/logtest.ts, .html, .css"],
        ["Sigma Rules Engine", "/analyst/siem-sigma", "Sigma rules manager, rule compiler, and real-time ClickHouse SQL query translation engine", "src/pages/siem-ai/sigma/siem-sigma.ts, .html, .css"]
    ]
    add_styled_table(det_pages_headers, det_pages_data, [1.8, 1.8, 2.2, 1.2])

    add_h2("4.3 How it works")
    add_bullet("1. Ingestion & Pre-decoding: Raw logs arriving from provigil-remoted or syslog listeners are split into timestamp, hostname, program name, and message by provigil-analysisd.")
    add_bullet("2. Multi-Tier Decoding: Decoders extract structured entities (srcip, dstip, srcport, dstport, user, protocol, action, status, url) using optimized regex and compiled parsers.")
    add_bullet("3. 8,400+ Rule Correlation: Evaluates decoded fields against hierarchical rulesets, frequency thresholds, sliding-window temporal correlations, and threat CDB lookup tables.")
    add_bullet("4. Sigma Engine Translation: siem-api compiles YAML Sigma rules into in-memory evaluators for live telemetry streams and ClickHouse SQL queries for historical threat hunting.")
    add_bullet("5. MITRE ATT&CK Tagging: Rules carry MITRE tactic and technique IDs, dynamically mapped against SQLite var/db/mitre.db to generate real-time attack coverage heatmaps.")
    add_bullet("6. Alert Dispatch (Levels 0–15): Events reaching alert thresholds are formatted as normalized Alert objects and streamed over the write-ahead platform stream to siem-api.")
    add_bullet("7. WebSocket Push Bus: siem-api tags alerts with tenant_id, batches inserts into ndr_<tenant>.siem_alerts, and broadcasts live alerts over /ws/alerts to connected SOC browsers.")

    # ---------------- MODULE 5 ----------------
    add_h1("Module 5 — Vulnerability Detection & CVE Management")
    add_h2("5.1 What it does")
    add_body("Vulnerability Detection evaluates host software discovered by the inventory engine against global vulnerability databases, including the National Vulnerability Database (NVD) and Open Source Vulnerabilities (OSV) feeds. It delivers cross-platform package vulnerability matching across native Windows software, Python pip modules, and npm global packages. The subsystem provides CVSS scoring, status tracking, per-agent and fleet-wide vulnerability dashboards, automated self-healing rescans, and customizable Excel audit reports.")

    add_h2("5.2 Pages")
    vuln_pages_headers = ["Page", "URL", "What it shows", "Front-end files"]
    vuln_pages_data = [
        ["Vulnerabilities", "/analyst/vulnerabilities", "Active CVE detections across all tenant agents, severity breakdown (Critical, High, Medium, Low), package search, CVSS scores, fixed versions, and Scan Now trigger", "src/pages/analyst/vulnerabilities/vulnerabilities.ts, .html, .css"],
        ["Agents → agent detail → Vulnerabilities tab", "/analyst/agents", "Filterable list of CVE vulnerabilities affecting the specific selected host, remediation recommendations, and patch details", "src/pages/analyst/agents/agents.ts, .html"],
        ["Vulnerability Excel Export", "/api/v1/vulnerabilities/report.xlsx", "Direct downloadable spreadsheet listing all active CVE detections, affected endpoints, packages, and severity for auditor handoff", "Generated dynamically by siem-api/src/vuln_report.rs"]
    ]
    add_styled_table(vuln_pages_headers, vuln_pages_data, [1.8, 1.8, 2.2, 1.2])

    add_h2("5.3 How it works")
    add_bullet("1. NVD and OSV Feed Sync: provigil-modulesd synchronizes CVE feeds from NVD, OSV, and vendor OVAL advisories, indexing them into an optimized local database (queue/vd).")
    add_bullet("2. Multi-Ecosystem Package Matching: Cross-references installed Windows applications, Python pip packages, and npm modules against CPE dictionaries and version comparison graphs.")
    add_bullet("3. CVSS Scoring & Severity Tagging: Computes CVSS v3.1 base scores, assigning severity ratings (Critical, High, Medium, Low) and capturing vendor remediation links.")
    add_bullet("4. Real-Time State Ingestion: Findings stream over the platform stream (kind 'V') into ClickHouse table ndr_<tenant>.siem_vulnerability_state (ReplacingMergeTree).")
    add_bullet("5. Self-Healing Re-Scans: If an agent's vulnerability state is wiped following a reboot while its package inventory remains unchanged, heal_later triggers an automatic targeted rescan after 120 seconds.")
    add_bullet("6. Customizable Excel Reporting: Exports complete vulnerability audit workbooks containing CVE IDs, CVSS scores, installed vs fixed versions, and remediation instructions.")

    # ---------------- MODULE 6 ----------------
    add_h1("Module 6 — Active Response & Incident Remediation")
    add_h2("6.1 What it does")
    add_body("Active Response delivers sub-second automated and analyst-driven endpoint threat containment. It executes native firewall blocks (Windows netsh, Linux iptables, or null routing) with timed undo mechanisms that survive agent service restarts, terminates malicious process trees, isolates compromised hosts from corporate networks, quarantines suspicious files with atomic restore capabilities, conducts on-demand YARA memory/file scans, enforces anti-tampering protection, and applies repeat-offender escalation policies.")

    add_h2("6.2 Pages")
    ar_pages_headers = ["Page", "URL", "What it shows", "Front-end files"]
    ar_pages_data = [
        ["Active Response", "/analyst/active-response", "Live table of active and released firewall blocks across the fleet, target IP, trigger agent, operator reason, manual block submission form, and one-click unblock button", "src/pages/analyst/active-response/active-response.ts, .html, .css"],
        ["Agents → agent detail → Response tab", "/analyst/agents", "Host-level remediation actions for the selected endpoint: Block IP, Kill Process, Quarantine File, Network Isolation, and Service Restart", "src/pages/analyst/agents/agents.ts, .html"],
        ["SOAR Playbooks", "/analyst/soar", "Automated threat containment playbooks linking detection rule alerts directly to Active Response blocks", "src/pages/analyst/soar/soar.ts, .html, .css"],
        ["EDR Tamper Protection", "/analyst/edr/tamper", "Anti-tamper policy controls, agent service permission lock/unlock toggles, and scheduled maintenance windows", "src/pages/analyst/settings/settings.ts"]
    ]
    add_styled_table(ar_pages_headers, ar_pages_data, [1.8, 1.8, 2.2, 1.2])

    add_h2("6.3 How it works")
    add_bullet("1. Multi-Vector Containment Triggers: Remediation is initiated automatically by rule alerts / SOAR playbooks, or manually by SOC analysts through the console.")
    add_bullet("2. Secure Command Dispatch: Commands are formatted into datagrams (e.g. netsh3600, kill-process0) and sent via AES-256 encrypted wire channels to the agent.")
    add_bullet("3. Native Host Execution: The agent executes containment actions using native OS tools (netsh advfirewall, iptables, taskkill /F /PID, icacls deny) with zero external script dependencies.")
    add_bullet("4. Timed Undo Surviving Restarts: Active firewall blocks are tracked in persistent agent state files. If the endpoint reboots during a block window, the agent automatically restores the block and unblocks only after the remaining time expires.")
    add_bullet("5. Repeat-Offender Escalation: Attacking IPs triggering repeated alerts within a sliding window are escalated automatically from 10 minutes (600s) to 1 hour (3600s), and up to 24 hours (86400s).")
    add_bullet("6. Host Isolation with Whitelisting: Isolates network interfaces while explicitly permitting bi-directional encrypted communication to MANAGER_IP, preserving SOC connectivity.")
    add_bullet("7. File Quarantine & Atomic Restore: Suspicious payloads are moved to an ACL-locked quarantine directory with SHA256 verification and can be restored with a single click.")

    # ---------------- MODULE 7 ----------------
    add_h1("Module 7 — Syslog Ingestion & Network Appliance Monitoring")
    add_h2("7.1 What it does")
    add_body("Syslog Ingestion collects security event streams from agentless network infrastructure, including enterprise firewalls (FortiGate, Palo Alto, Cisco ASA/FTD), switches, routers, VPN concentrators, and DNS servers. The subsystem operates concurrent multi-protocol listeners on UDP 514 (RFC 3164), TCP 601 (RFC 5424), and TLS 6514 (RFC 5425). It provides strict per-tenant mutual TLS (mTLS) with client certificates issued by the platform's private CA, IP-based tenant routing for unencrypted appliances, and MaxMind GeoIP attack mapping.")

    add_h2("7.2 Pages")
    syslog_pages_headers = ["Page", "URL", "What it shows", "Front-end files"]
    syslog_pages_data = [
        ["Syslog Devices & Sources", "/tenant-admin/syslog-devices", "Management of TLS syslog devices (mTLS certificates, fingerprint tracking, last-seen timestamps) and plain syslog source IP mappings for the tenant", "src/pages/tenant-admin/syslog-devices/syslog-devices.ts, .html"],
        ["Network Map & Assets", "/analyst/network-map, /analyst/assets", "Visual topology of discovered network appliances, active IP addresses, MAC assignments, and device communication flows", "src/pages/analyst/network-map/network-map.ts, .html, .css"],
        ["Global Threat Map", "/analyst/threat-map", "Real-time geographical attack map resolving inbound firewall and appliance IP addresses to physical coordinates via MaxMind GeoIP", "src/pages/analyst/threat-map/threat-map.ts, .html, .css"]
    ]
    add_styled_table(syslog_pages_headers, syslog_pages_data, [1.8, 1.8, 2.2, 1.2])

    add_h2("7.3 How it works")
    add_bullet("1. Concurrent Multi-Protocol Listeners: siem-api runs asynchronous Tokio listeners on UDP 514, TCP 601, and TLS 6514 at startup.")
    add_bullet("2. Mutual TLS & Certificate Fingerprints: Network appliances connecting to TLS 6514 present x509 client certificates issued by the platform private CA. The receiver resolves the SHA-256 fingerprint against the tenant registry to identify tenant ownership.")
    add_bullet("3. IP-Based Tenant Routing: Unencrypted syslog messages on UDP 514 / TCP 601 are matched against tenant IP mappings, routing private subnet and VPN logs to the appropriate tenant.")
    add_bullet("4. RFC Message Normalization: Normalizes RFC 3164 and RFC 5424 logs, extracting facility, severity, timestamp, hostname, process, and message payload.")
    add_bullet("5. Rule Analysis & Event Ingestion: Normalized events stream to provigil-analysisd for firewall rule evaluation and are committed to ClickHouse table ndr_<tenant>.siem_events.")
    add_bullet("6. GeoIP Threat Resolution: External IP addresses extracted from appliance logs are resolved via geomap.rs to latitude, longitude, country, and ISP, populating real-time attack maps.")
    add_bullet("7. Instant Certificate Revocation: Compromised appliance certificates can be revoked instantly from the UI, severing active TLS connections on the next byte.")

    doc.save(output_path)
    print(f"[OK] Document generated successfully at: {output_path}")

if __name__ == "__main__":
    out = os.path.abspath("E:/wazhu-Siem-code/ProVigil_Technical_Documentation_Part_1.docx")
    build_technical_doc(out)
