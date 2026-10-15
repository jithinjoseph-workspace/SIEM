import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_complete_architecture_diagram(output_image_path="Provigil_AETHER_Complete_Architecture_Diagram.png"):
    # High resolution canvas: 22 inches wide x 30 inches tall at 200 DPI = 4400 x 6000 pixels
    fig, ax = plt.subplots(figsize=(22, 30), dpi=200)
    fig.patch.set_facecolor('#0B1120') # Deep midnight navy
    ax.set_facecolor('#0B1120')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Helper: Draw rounded card
    def draw_card(x, y, w, h, bg_color, border_color, border_width=1.5, radius=1.0):
        box = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad=0,rounding_size={radius}",
            facecolor=bg_color,
            edgecolor=border_color,
            linewidth=border_width,
            zorder=2
        )
        ax.add_patch(box)
        return box

    # Helper: Draw badge
    def draw_badge(x, y, text, bg_color, text_color='#FFFFFF', fontsize=8.5):
        padding = len(text) * 0.42 + 1.2
        box = patches.FancyBboxPatch(
            (x - padding/2, y - 0.65), padding, 1.3,
            boxstyle="round,pad=0,rounding_size=0.6",
            facecolor=bg_color,
            edgecolor='none',
            zorder=4
        )
        ax.add_patch(box)
        ax.text(x, y, text, ha='center', va='center', color=text_color,
                fontsize=fontsize, fontweight='bold', fontfamily='sans-serif', zorder=5)

    # Helper: Draw Arrow
    def draw_arrow(x1, y1, x2, y2, color='#38BDF8', width=1.5, label=None, label_pos=0.5, label_offset=(0, 0)):
        ax.annotate(
            '', xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(
                arrowstyle='->,head_width=0.35,head_length=0.55',
                color=color,
                lw=width,
                shrinkA=2,
                shrinkB=2
            ),
            zorder=3
        )
        if label:
            lx = x1 + (x2 - x1) * label_pos + label_offset[0]
            ly = y1 + (y2 - y1) * label_pos + label_offset[1]
            ax.text(lx, ly, label, ha='center', va='center', color=color,
                    fontsize=8.0, fontweight='bold', fontfamily='sans-serif',
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='#0B1120', edgecolor=color, lw=0.8),
                    zorder=6)

    # ==================== MAIN TITLE & HEADER (y: 96 to 99) ====================
    ax.text(50, 98.2, "PROVIGIL AETHER - COMPLETE ENTERPRISE XDR ARCHITECTURE", ha='center', va='center',
            color='#F8FAFC', fontsize=22, fontweight='bold', fontfamily='sans-serif')
    ax.text(50, 96.8, "Comprehensive Topology: Edge Ingress  •  Rust Microservices  •  Core SIEM Daemons  •  Host Agent Internal Subsystems  •  Big Data Layer",
            ha='center', va='center', color='#38BDF8', fontsize=10.5, fontfamily='sans-serif')

    # ==================== TIER 1: CLIENTS & SOC USERS (y: 89.5 to 95) ====================
    draw_card(2.5, 89.5, 95, 5.8, '#131D33', '#1E293B', border_width=1.5, radius=1.2)
    ax.text(4.5, 94.3, "TIER 1: CLIENT & SOC USER INTERFACES", color='#94A3B8', fontsize=9.5, fontweight='bold', fontfamily='sans-serif')

    users = [
        (4.5, 90.3, 28, 3.8, "Security Analysts (SOC)", "Alert Triage, Incident Response, ARIA AI Copilot", "#0284C7"),
        (36.0, 90.3, 28, 3.8, "Tenant Administrators", "Analyst Provisioning, SIEM/NDR Toggles, Agent Keys", "#0D9488"),
        (67.5, 90.3, 28, 3.8, "Super Administrators", "Cross-Tenant Governance, Global Node Health & Licenses", "#7C3AED")
    ]
    for ux, uy, uw, uh, utitle, udesc, uaccent in users:
        draw_card(ux, uy, uw, uh, '#1E293B', uaccent, border_width=1.5, radius=0.8)
        draw_badge(ux + 3.0, uy + uh - 0.9, "USER", uaccent, fontsize=7)
        ax.text(ux + 6.5, uy + uh - 0.9, utitle, color='#F8FAFC', fontsize=9, fontweight='bold', fontfamily='sans-serif')
        ax.text(ux + 1.5, uy + 1.0, udesc, color='#CBD5E1', fontsize=8, fontfamily='sans-serif')

    draw_arrow(50, 89.5, 50, 84.5, color='#38BDF8', width=1.8, label="HTTPS / WSS (Ports 80, 443)", label_pos=0.5)

    # ==================== TIER 2: EDGE INGRESS GATEWAY - CADDY (y: 77 to 84.5) ====================
    draw_card(2.5, 77.0, 95, 7.5, '#1E1B4B', '#6366F1', border_width=2.0, radius=1.2)
    ax.text(4.5, 83.6, "TIER 2: EDGE REVERSE PROXY & AUTOMATIC TLS (Caddy Alpine)", color='#A5B4FC', fontsize=10.5, fontweight='bold', fontfamily='sans-serif')
    draw_badge(88, 83.6, "CONTAINER: xdr-caddy-proxy", '#4F46E5', fontsize=8)

    caddy_info = (
        "• Automatic TLS (Let's Encrypt / ZeroSSL)  |  HTTP/1.1, HTTP/2, HTTP/3 QUIC  |  Compression: zstd & gzip\n"
        "• Security Headers (nosniff, SAMEORIGIN, strict-origin)  |  50MB Request Body Buffer for High-Volume Telemetry\n"
        "• Path-Based Reverse Proxying: Decouples frontend ports from internal Rust microservices and WebSockets"
    )
    ax.text(5.5, 80.3, caddy_info, color='#E0E7FF', fontsize=8.5, fontfamily='sans-serif', linespacing=1.25)

    pills = [
        (13, 78.2, "/api/auth/*  ->  :3001", '#10B981'),
        (37, 78.2, "/api/v1/*  ->  :8088", '#0EA5E9'),
        (61, 78.2, "/ws/alerts  ->  :8088 (WS)", '#8B5CF6'),
        (85, 78.2, "/*  ->  Angular 19 SPA", '#EC4899')
    ]
    for px, py, ptxt, pcol in pills:
        draw_badge(px, py, ptxt, pcol, fontsize=7.5)

    draw_arrow(14, 77.0, 14, 71.5, color='#10B981', width=1.5, label="Auth REST", label_pos=0.45)
    draw_arrow(39, 77.0, 39, 71.5, color='#0EA5E9', width=1.8, label="SIEM REST & /downloads", label_pos=0.45)
    draw_arrow(63, 77.0, 63, 71.5, color='#8B5CF6', width=1.5, label="Real-Time Alerts WS", label_pos=0.45)
    draw_arrow(86, 77.0, 86, 71.5, color='#EC4899', width=1.5, label="SOC Static SPA", label_pos=0.45)

    # ==================== TIER 3: RUST MICROSERVICES & SOC UI (y: 60.5 to 71.5) ====================
    draw_card(2.5, 60.0, 95, 11.5, '#0F172A', '#334155', border_width=1.5, radius=1.2)
    ax.text(4.5, 70.5, "TIER 3: RUST APPLICATION MICROSERVICES & SOC FRONTEND", color='#94A3B8', fontsize=10.5, fontweight='bold', fontfamily='sans-serif')

    # Card 1: Auth Service
    draw_card(4.5, 61.0, 21.0, 8.5, '#064E3B', '#10B981', border_width=1.8, radius=0.8)
    draw_badge(15.0, 68.5, "AUTH SERVICE (:3001)", '#059669', fontsize=8)
    ax.text(5.5, 66.8, "Rust • Axum Microservice", color='#6EE7B7', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    auth_desc = (
        "• Multi-tenant JWT generation\n"
        "• Tenant & User provisioning\n"
        "• Feature Licensing (ndr, siem)\n"
        "• RBAC role verification\n"
        "• In-memory session checks"
    )
    ax.text(5.5, 61.6, auth_desc, color='#ECFDF5', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # Card 2: SIEM Core API
    draw_card(27.5, 61.0, 30.5, 8.5, '#0C4A6E', '#0EA5E9', border_width=2.0, radius=0.8)
    draw_badge(42.7, 68.5, "SIEM API CORE ENGINE (:8088)", '#0284C7', fontsize=8)
    ax.text(28.5, 66.8, "Rust • Tokio Event Core", color='#7DD3FC', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    siem_desc = (
        "• Real-time 1,400+ XML/Sigma Rule Engine\n"
        "• Temporal sliding window correlator\n"
        "• Agent enrollment & X-Tenant-Key isolation\n"
        "• /downloads package server (.exe, install.sh)\n"
        "• Real-time WebSocket alerts broadcast bus"
    )
    ax.text(28.5, 61.6, siem_desc, color='#F0F9FF', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # Card 3: NDR Sensor API
    draw_card(60.0, 61.0, 17.0, 8.5, '#134E4A', '#14B8A6', border_width=1.8, radius=0.8)
    draw_badge(68.5, 68.5, "NDR API (:8090)", '#0D9488', fontsize=8)
    ax.text(61.0, 66.8, "Rust • Flow Engine", color='#5EEAD4', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    ndr_desc = (
        "• Deep packet inspection\n"
        "• TLS/JA4 fingerprinting\n"
        "• Flow anomaly analysis\n"
        "• Zeek/Suricata sync"
    )
    ax.text(61.0, 62.0, ndr_desc, color='#F0FDFA', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # Card 4: Angular 19 SOC Frontend
    draw_card(79.0, 61.0, 16.5, 8.5, '#4A044E', '#C026D3', border_width=1.8, radius=0.8)
    draw_badge(87.2, 68.5, "ANGULAR 19 SOC UI", '#A21CAF', fontsize=8)
    ax.text(80.0, 66.8, "Single Page App (SPA)", color='#F5D0FE', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    ui_desc = (
        "• Tenant Admin Console\n"
        "• Incident Investigation\n"
        "• Endpoint Fleet Overview\n"
        "• MITRE ATT&CK Matrix\n"
        "• ARIA AI Security Copilot"
    )
    ax.text(80.0, 61.6, ui_desc, color='#FDF4FF', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # Arrows to Daemons & Storage
    draw_arrow(20, 60.0, 25, 55.0, color='#10B981', width=1.5, label="SQL Queries", label_pos=0.5)
    draw_arrow(43, 60.0, 35, 55.0, color='#0EA5E9', width=2.0, label="Events Batch Ingestion", label_pos=0.5)

    # ==================== TIER 4: BIG DATA STORAGE & CACHING (y: 47 to 55) ====================
    draw_card(2.5, 46.5, 95, 8.5, '#1E293B', '#475569', border_width=1.5, radius=1.2)
    ax.text(4.5, 54.0, "TIER 4: BIG DATA STORAGE & IN-MEMORY CACHE TIER", color='#94A3B8', fontsize=10.5, fontweight='bold', fontfamily='sans-serif')

    # ClickHouse Card
    draw_card(4.5, 47.3, 55.0, 6.0, '#881337', '#F43F5E', border_width=2.0, radius=0.8)
    draw_badge(18.5, 52.3, "CLICKHOUSE COLUMNAR ENGINE (:8123 / :9000)", '#E11D48', fontsize=8)
    ax.text(5.5, 50.8, "Container: xdr-clickhouse • Database: ndr", color='#FDA4AF', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    ch_info = (
        "• Partitioned by month, indexed by (tenant_id, timestamp) for strict multi-tenant isolation\n"
        "• Tables: siem_events, siem_alerts, siem_agents, agent_registry, tenant_agent_keys, xdr_incidents\n"
        "• High-throughput bulk stream writes: 100,000+ events/sec with sub-second analytical aggregations"
    )
    ax.text(5.5, 47.8, ch_info, color='#FFF1F2', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # Valkey Card
    draw_card(62.0, 47.3, 33.5, 6.0, '#78350F', '#F59E0B', border_width=2.0, radius=0.8)
    draw_badge(78.5, 52.3, "VALKEY / REDIS CACHE (:6379)", '#D97706', fontsize=8)
    ax.text(63.0, 50.8, "Container: xdr-valkey", color='#FDE68A', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    val_info = (
        "• Active JWT Token validation & revocation blacklist\n"
        "• Real-time rate limiting & microservice pub/sub bus\n"
        "• Agent keepalive temporal cache & heartbeat sync"
    )
    ax.text(63.0, 47.8, val_info, color='#FEF3C7', fontsize=7.5, fontfamily='sans-serif', linespacing=1.2)

    # ==================== TIER 5: CORE MANAGER DAEMONS & WIRE PROTOCOL (y: 33.5 to 44.5) ====================
    draw_card(2.5, 33.0, 95, 11.5, '#172554', '#2563EB', border_width=1.8, radius=1.2)
    ax.text(4.5, 43.5, "TIER 5: MANAGER DAEMONS & AGENT WIRE GATEWAY SUBSYSTEMS", color='#93C5FD', fontsize=10.5, fontweight='bold', fontfamily='sans-serif')

    daemons = [
        (4.5, 34.0, 21.5, 8.5, "wazuh-remoted (:1514)", "Agent Wire Protocol",
         "• AES-256 Wire Encryption\n• 50,000+ Concurrent Agents\n• TCP/UDP connection pool\n• client.keys mutual auth\n• High-throughput buffer", '#2563EB'),
        (28.0, 34.0, 22.0, 8.5, "wazuh-analysisd", "Detection Engine",
         "• Pre-decoders & XML rules\n• Dynamic learned parsers\n• Threat scoring & MITRE\n• Sliding window correlation\n• Generates siem_alerts", '#0284C7'),
        (52.0, 34.0, 21.0, 8.5, "wazuh-db & vuln-detector", "Database & CVE Audit",
         "• wdb SQLite sync daemon\n• Agent state & sysinfo sync\n• CVE lookup (NVD/OVAL)\n• Vulnerability scoring\n• CIS benchmark evaluator", '#0D9488'),
        (75.0, 34.0, 20.5, 8.5, "Syslog / Integratord", "Appliance & Webhooks",
         "• Syslog :514 UDP/TCP, :601\n• RFC 5424/6587 receiver\n• Integrations: VirusTotal, \n  Slack, Shuffle, Jira, Webhooks\n• Alert notification maild", '#6366F1')
    ]
    for dx, dy, dw, dh, dtitle, dsub, ddesc, dcol in daemons:
        draw_card(dx, dy, dw, dh, '#1E293B', dcol, border_width=1.5, radius=0.8)
        draw_badge(dx + dw/2, dy + dh - 0.9, dtitle, dcol, fontsize=7.5)
        ax.text(dx + 1.0, dy + dh - 2.2, dsub, color='#94A3B8', fontsize=8, fontweight='bold', fontfamily='sans-serif')
        ax.text(dx + 1.0, dy + 0.6, ddesc, color='#F8FAFC', fontsize=7.2, fontfamily='sans-serif', linespacing=1.2)

    # SECURED NETWORK BOUNDARY / FIREWALL
    ax.plot([2.5, 97.5], [30.5, 30.5], color='#EF4444', linestyle='--', lw=2.0, zorder=2)
    ax.text(50, 30.5, "  [ SECURED NETWORK BOUNDARY  •  CORPORATE FIREWALL & DMZ ]  ", color='#F87171', fontsize=9.5,
            fontweight='bold', fontfamily='sans-serif', ha='center', va='center',
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#0B1120', edgecolor='#EF4444', lw=1.2), zorder=4)

    # Connections across firewall
    draw_arrow(23, 27.0, 23, 33.0, color='#38BDF8', width=2.0, label="Port 1514 (AES-256 Wire)", label_pos=0.5, label_offset=(7, 0))
    draw_arrow(46, 27.0, 46, 33.0, color='#0EA5E9', width=1.5, label="Port 8088 (Enrollment)", label_pos=0.5, label_offset=(-7, 0))
    draw_arrow(82, 27.0, 82, 33.0, color='#818CF8', width=1.8, label="Port 514/601 (Syslog)", label_pos=0.5, label_offset=(-7, 0))

    # ==================== TIER 6: COMPREHENSIVE HOST AGENT SUBSYSTEMS (y: 1.5 to 27) ====================
    draw_card(2.5, 1.0, 95, 26.0, '#042F2E', '#0D9488', border_width=2.0, radius=1.2)
    ax.text(4.5, 26.0, "TIER 6: COMPREHENSIVE ENDPOINT AGENT ARCHITECTURE & HOST INTERNAL SUBSYSTEMS", color='#5EEAD4', fontsize=11, fontweight='bold', fontfamily='sans-serif')

    # ---------------- HOST 1: WINDOWS ENDPOINT HOST (x: 4.5, y: 1.8, w: 43.5, h: 23.2) ----------------
    draw_card(4.5, 1.8, 44.5, 23.2, '#0F2927', '#14B8A6', border_width=1.8, radius=1.0)
    draw_badge(26.7, 24.0, "WINDOWS HOST ENDPOINT ARCHITECTURE (WazuhSvc)", '#0F766E', fontsize=8.5)
    ax.text(5.5, 22.8, "Process: wazuh-agent.exe  •  Path: %ProgramFiles(x86)%\\ossec-agent\\  •  Service: WazuhSvc",
            color='#99F6E4', fontsize=7.8, fontweight='bold', fontfamily='sans-serif')

    # Sub-modules inside Windows Host:
    win_subsystems = [
        # (x, y, w, h, title, details)
        (5.5, 16.5, 20.5, 5.8, "Logcollector & EventLog",
         "• Channels: Application, Security, System\n• Windows EventChannel API (XML push)\n• IIS, DHCP, Exchange, PowerShell logs\n• Text file log multi-line streaming"),
        (27.0, 16.5, 21.0, 5.8, "Sysmon Subsystem (IDs 1-20)",
         "• ID 1: ProcessCreate & CommandLine\n• ID 3: NetworkConnection & Remote IPs\n• ID 7: ImageLoaded / DLL Injection\n• ID 8: CreateRemoteThread / Mimikatz\n• ID 10/11/13: ProcessAccess & Registry"),
        (5.5, 9.8, 20.5, 6.0, "Syscollector (Host Inventory)",
         "• Hardware Specs (CPU, RAM, Disks)\n• OS Build, Patch Levels & Hotfixes\n• Network Adapters, MACs, IPv4/IPv6, Routes\n• Open Ports & Listening Sockets\n• Running Processes, PIDs & Loaded Modules\n• Complete Installed Software Registry"),
        (27.0, 9.8, 21.0, 6.0, "File & Registry Integrity (FIM)",
         "• Real-time Whodata (captures exact user)\n• SHA256 / SHA1 / MD5 hash tracking\n• Inode, file size, owner & permission audit\n• Registry Keys: Run, RunOnce, Winlogon,\n  Services, AppInit_DLLs persistence\n• Tamper-resistant local DB cache"),
        (5.5, 2.5, 20.5, 6.6, "SCA, CIS & Rootcheck",
         "• Center for Internet Security (CIS) checks\n• Account lockout & Password policy audit\n• Windows Defender / AV active status\n• BitLocker & Firewall configuration audit\n• Detects rootkits, hidden files & ports"),
        (27.0, 2.5, 21.0, 6.6, "Active Response & Agent Buffer",
         "• execd: Local automated containment\n• Dynamic Windows Firewall IP drop rules\n• Malicious Process termination (taskkill)\n• Compromised User Account disablement\n• Leaky-bucket in-memory queue & disk cache\n• client.keys AES-256 session handshake")
    ]
    for sx, sy, sw, sh, stitle, sdesc in win_subsystems:
        draw_card(sx, sy, sw, sh, '#134E4A', '#2DD4BF', border_width=1.2, radius=0.6)
        ax.text(sx + 0.8, sy + sh - 1.1, stitle, color='#A7F3D0', fontsize=8, fontweight='bold', fontfamily='sans-serif')
        ax.text(sx + 0.8, sy + 0.5, sdesc, color='#F0FDFA', fontsize=7.0, fontfamily='sans-serif', linespacing=1.18)

    # ---------------- HOST 2: LINUX HOST & NETWORK APPLIANCES (x: 50.5, y: 1.8, w: 45.5, h: 23.2) ----------------
    draw_card(50.5, 1.8, 45.5, 23.2, '#1E293B', '#38BDF8', border_width=1.8, radius=1.0)
    draw_badge(73.2, 24.0, "LINUX HOST, NDR SENSORS & APPLIANCES", '#0284C7', fontsize=8.5)
    ax.text(51.5, 22.8, "Linux Daemon (siem-agent-linux)  •  Network Sensor (Zeek/Suricata)  •  Syslog Devices",
            color='#BAE6FD', fontsize=7.8, fontweight='bold', fontfamily='sans-serif')

    linux_subsystems = [
        (51.5, 16.5, 21.5, 5.8, "Linux Auditd Kernel Hook",
         "• Netlink socket interception\n• execve syscall process monitoring\n• connect / bind socket tracing\n• ptrace process injection tracking\n• Privileged command execution (sudo)"),
        (74.0, 16.5, 21.0, 5.8, "Systemd Journal & Logs",
         "• /var/log/secure & auth.log\n• SSH brute force & login auditing\n• systemd unit failure tracking\n• Web server logs: Nginx, Apache\n• Database logs: MySQL, PostgreSQL"),
        (51.5, 9.8, 21.5, 6.0, "Linux Syscollector & FIM",
         "• inotify kernel real-time watchers\n• /etc, /bin, /sbin, /usr/bin hashing\n• dpkg, rpm, pacman package inventory\n• Listening ports & kernel routing table\n• /proc filesystem process tree analysis"),
        (74.0, 9.8, 21.0, 6.0, "Linux SCA & Rootcheck",
         "• CIS Linux Distribution Benchmarks\n• SSH daemon configuration auditing\n• Kernel hardening (sysctl parameters)\n• Trojan horse & stealth file discovery\n• Promiscuous network interface alert"),
        (51.5, 2.5, 21.5, 6.6, "NDR Network Sensor Engine",
         "• Passive SPAN / TAP packet sniffing\n• Zeek protocol analyzers (HTTP, DNS, TLS)\n• JA4 / JA4S cryptographic fingerprinting\n• ARP anomaly detector (ndr-arp.zeek)\n• Flow byte/packet volume counters"),
        (74.0, 2.5, 21.0, 6.6, "Network Appliances & Agentless",
         "• Firewalls: FortiGate, Palo Alto, Cisco\n• Switches & Routers (Cisco, Juniper)\n• Agentless SSH monitoring (siem-agentlessd)\n• Linux Active Response: iptables / nftables\n• Drops malicious IPs in < 1 second")
    ]
    for sx, sy, sw, sh, stitle, sdesc in linux_subsystems:
        draw_card(sx, sy, sw, sh, '#0F172A', '#38BDF8', border_width=1.2, radius=0.6)
        ax.text(sx + 0.8, sy + sh - 1.1, stitle, color='#7DD3FC', fontsize=8, fontweight='bold', fontfamily='sans-serif')
        ax.text(sx + 0.8, sy + 0.5, sdesc, color='#F0F9FF', fontsize=7.0, fontfamily='sans-serif', linespacing=1.18)

    plt.tight_layout()
    plt.savefig(output_image_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f"Complete architecture diagram saved to: {output_image_path}")

if __name__ == "__main__":
    draw_complete_architecture_diagram()
