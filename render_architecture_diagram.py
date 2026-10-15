import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_architecture_diagram(output_image_path="Provigil_AETHER_Architecture_Diagram.png"):
    # High resolution canvas (18 inches x 22 inches at 200 DPI = 3600 x 4400 pixels)
    fig, ax = plt.subplots(figsize=(18, 22), dpi=200)
    fig.patch.set_facecolor('#0B1120') # Deep midnight navy
    ax.set_facecolor('#0B1120')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Helper: Draw rounded card
    def draw_card(x, y, w, h, bg_color, border_color, border_width=1.5, radius=1.2):
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
    def draw_badge(x, y, text, bg_color, text_color='#FFFFFF', fontsize=9):
        padding = len(text) * 0.45 + 1.2
        box = patches.FancyBboxPatch(
            (x - padding/2, y - 0.7), padding, 1.4,
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
                arrowstyle='->,head_width=0.4,head_length=0.6',
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
                    fontsize=8.5, fontweight='bold', fontfamily='sans-serif',
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='#0B1120', edgecolor=color, lw=0.8),
                    zorder=6)

    # ==================== MAIN TITLE & HEADER ====================
    ax.text(50, 97.5, "PROVIGIL AETHER - UNIFIED XDR ARCHITECTURE", ha='center', va='center',
            color='#F8FAFC', fontsize=22, fontweight='bold', fontfamily='sans-serif')
    ax.text(50, 95.8, "End-to-End System Topology: Caddy Ingress  •  Rust Microservices  •  Multi-Agent Fleet  •  ClickHouse Big Data",
            ha='center', va='center', color='#38BDF8', fontsize=11, fontfamily='sans-serif')

    # ==================== TIER 1: CLIENTS & USERS (y: 88 to 94) ====================
    # Outer Group
    draw_card(3, 87.5, 94, 6.8, '#131D33', '#1E293B', border_width=1.5, radius=1.5)
    ax.text(5, 93.3, "CLIENT & SOC USERS TIER", color='#94A3B8', fontsize=10, fontweight='bold', fontfamily='sans-serif')

    # Sub-cards: SOC Analysts, Tenant Admins, Super Admin
    users = [
        (6, 88.5, 27, 4.5, "Security Analysts (SOC)", "Alert Triage, Incidents, Threat Hunting", "#0284C7"),
        (36.5, 88.5, 27, 4.5, "Tenant Administrators", "User Provisioning, SIEM/NDR Toggles", "#0D9488"),
        (67, 88.5, 27, 4.5, "Super Administrators", "Cross-Tenant Governance & Licensing", "#7C3AED")
    ]
    for ux, uy, uw, uh, utitle, udesc, uaccent in users:
        draw_card(ux, uy, uw, uh, '#1E293B', uaccent, border_width=1.8, radius=1.0)
        draw_badge(ux + 3.5, uy + uh - 1.1, "USER", uaccent, fontsize=7.5)
        ax.text(ux + 7.5, uy + uh - 1.1, utitle, color='#F8FAFC', fontsize=10, fontweight='bold', fontfamily='sans-serif')
        ax.text(ux + 2, uy + 1.2, udesc, color='#CBD5E1', fontsize=8.5, fontfamily='sans-serif')

    # Downward connection to Caddy
    draw_arrow(50, 87.5, 50, 81.5, color='#38BDF8', width=2.0, label="HTTPS / WSS :443  (HTTP :80 -> 301 redirect)", label_pos=0.5)

    # ==================== TIER 2: EDGE REVERSE PROXY - CADDY (y: 73 to 81.5) ====================
    draw_card(3, 72.8, 94, 8.7, '#1E1B4B', '#6366F1', border_width=2.0, radius=1.5)
    ax.text(5, 80.5, "EDGE INGRESS GATEWAY  •  CADDY PROXY", color='#A5B4FC', fontsize=11, fontweight='bold', fontfamily='sans-serif')
    draw_badge(88, 80.5, "CONTAINER: xdr-caddy-proxy", '#4F46E5', fontsize=8)

    # Caddy details card
    caddy_info = (
        "• Automatic TLS for SITE_DOMAIN (Let's Encrypt / ZeroSSL) + HTTP->HTTPS redirect  |  HTTP/2 & HTTP/3 QUIC  |  zstd & gzip\n"
        "• Strict Security Headers (nosniff, SAMEORIGIN, strict-origin)  |  50MB Large Batch Request Body Buffer\n"
        "• Routes: /api/auth/* -> :3001  •  /api/ndr/*, /ws/ndr/* -> :8090  •  /api/*, /downloads/*, /ws/alerts -> :8088  •  /* -> SPA"
    )
    ax.text(6, 76.5, caddy_info, color='#E0E7FF', fontsize=9, fontfamily='sans-serif', linespacing=1.3)

    # Dispatch Pills
    pills = [
        (13, 74.0, "/api/auth/*  ->  :3001", '#10B981'),
        (37, 74.0, "/api/v1/*  ->  :8088", '#0EA5E9'),
        (61, 74.0, "/ws/alerts  ->  :8088 (WS)", '#8B5CF6'),
        (85, 74.0, "/*  ->  Angular 19 SPA", '#EC4899')
    ]
    for px, py, ptxt, pcol in pills:
        draw_badge(px, py, ptxt, pcol, fontsize=8)

    # Multi-arrows from Caddy to Microservices
    draw_arrow(15, 72.8, 15, 66.5, color='#10B981', width=1.5, label="Auth REST", label_pos=0.45)
    draw_arrow(40, 72.8, 40, 66.5, color='#0EA5E9', width=1.8, label="SIEM API / Downloads", label_pos=0.45)
    draw_arrow(64, 72.8, 64, 66.5, color='#8B5CF6', width=1.5, label="WebSockets Bus", label_pos=0.45)
    draw_arrow(86, 72.8, 86, 66.5, color='#EC4899', width=1.5, label="SOC Static HTML5", label_pos=0.45)

    # ==================== TIER 3: MICROSERVICES APPLICATION LAYER (y: 53.5 to 66.5) ====================
    draw_card(3, 53.0, 94, 13.5, '#0F172A', '#334155', border_width=1.5, radius=1.5)
    ax.text(5, 65.3, "RUST MICROSERVICES & SOC FRONTEND TIER", color='#94A3B8', fontsize=11, fontweight='bold', fontfamily='sans-serif')

    # Card 1: Auth Service (:3001)
    draw_card(5, 54.2, 21, 9.8, '#064E3B', '#10B981', border_width=1.8, radius=1.0)
    draw_badge(15.5, 62.8, "AUTH SERVICE (:3001)", '#059669', fontsize=8.5)
    ax.text(6, 60.5, "Rust • Axum Microservice", color='#6EE7B7', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    auth_desc = (
        "• Multi-tenant JWT generation\n"
        "• Tenant & User provisioning\n"
        "• Feature Licensing (ndr, siem)\n"
        "• RBAC scope verification\n"
        "• Cache invalidation via Valkey"
    )
    ax.text(6, 55.0, auth_desc, color='#ECFDF5', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Card 2: SIEM API Engine (:8088)
    draw_card(28, 54.2, 30, 9.8, '#0C4A6E', '#0EA5E9', border_width=2.0, radius=1.0)
    draw_badge(43, 62.8, "SIEM API ENGINE (:8088)", '#0284C7', fontsize=8.5)
    ax.text(29, 60.5, "Rust • Tokio Event Core", color='#7DD3FC', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    siem_desc = (
        "• Real-time 1,400+ XML/Sigma Rule Engine\n"
        "• Temporal sliding window threat correlator\n"
        "• Agent enrollment over HTTPS + tenant key\n"
        "• /downloads package server (.exe, install.sh)\n"
        "• Durable ingest: file offset saved after ClickHouse commit"
    )
    ax.text(29, 55.0, siem_desc, color='#F0F9FF', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Card 3: NDR Sensor API (:8090)
    draw_card(60, 54.2, 17, 9.8, '#134E4A', '#14B8A6', border_width=1.8, radius=1.0)
    draw_badge(68.5, 62.8, "NDR API (:8090)", '#0D9488', fontsize=8.5)
    ax.text(61, 60.5, "Rust • Network Sensor", color='#5EEAD4', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    ndr_desc = (
        "• Deep packet flow telemetry\n"
        "• TLS/JA4 fingerprinting\n"
        "• Protocol anomaly scoring\n"
        "• Zeek / Suricata log sync"
    )
    ax.text(61, 55.5, ndr_desc, color='#F0FDFA', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Card 4: Angular 19 SOC Frontend
    draw_card(79, 54.2, 16.5, 9.8, '#4A044E', '#C026D3', border_width=1.8, radius=1.0)
    draw_badge(87.2, 62.8, "ANGULAR 19 UI", '#A21CAF', fontsize=8.5)
    ax.text(80, 60.5, "Dark Mode SOC Interface", color='#F5D0FE', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    ui_desc = (
        "• Tenant Admin Console\n"
        "• Unified Alert Triage\n"
        "• Endpoint Fleet Overview\n"
        "• MITRE ATT&CK Matrix\n"
        "• ARIA AI Security Copilot"
    )
    ax.text(80, 55.0, ui_desc, color='#FDF4FF', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Arrows to Database Tier
    draw_arrow(20, 53.0, 25, 47.0, color='#10B981', width=1.5, label="SQL Queries", label_pos=0.5)
    draw_arrow(43, 53.0, 35, 47.0, color='#0EA5E9', width=2.0, label="High-Speed Batch Ingest", label_pos=0.5)
    draw_arrow(23, 53.0, 75, 47.0, color='#F59E0B', width=1.3, label="Sessions", label_pos=0.7)

    # ==================== TIER 4: STORAGE & CACHING TIER (y: 37 to 47) ====================
    draw_card(3, 36.5, 94, 10.5, '#1E293B', '#475569', border_width=1.5, radius=1.5)
    ax.text(5, 45.8, "BIG DATA & IN-MEMORY CACHE TIER  (internal only: bound to 127.0.0.1, never exposed)", color='#94A3B8', fontsize=11, fontweight='bold', fontfamily='sans-serif')

    # ClickHouse Container Card
    draw_card(5, 37.5, 54, 7.5, '#881337', '#F43F5E', border_width=2.0, radius=1.0)
    draw_badge(18, 43.8, "CLICKHOUSE COLUMNAR ENGINE (:8123 / :9000)", '#E11D48', fontsize=8.5)
    ax.text(6, 42.0, "Container: xdr-clickhouse • One database per tenant: ndr_<tenant>  (+ global ndr)", color='#FDA4AF', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    ch_tables = (
        "• Per tenant: siem_events (partitioned by month), siem_alerts, siem_agents\n"
        "• Global: agent_registry, tenant_agent_keys, xdr_incidents  •  scale out: replicas / ClickHouse Cloud\n"
        "• Columnar storage and compression for long retention and fast hunting queries"
    )
    ax.text(6, 38.2, ch_tables, color='#FFF1F2', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Valkey Container Card
    draw_card(62, 37.5, 33, 7.5, '#78350F', '#F59E0B', border_width=2.0, radius=1.0)
    draw_badge(78.5, 43.8, "VALKEY / REDIS CACHE (:6379)", '#D97706', fontsize=8.5)
    ax.text(63, 42.0, "Container: xdr-valkey", color='#FDE68A', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    valkey_desc = (
        "• Active JWT Token validation & revocation\n"
        "• Tenant session state and auth limits\n"
        "• Microservice pub/sub event distribution"
    )
    ax.text(63, 38.3, valkey_desc, color='#FEF3C7', fontsize=8, fontfamily='sans-serif', linespacing=1.25)

    # Arrow from Ingestion to ClickHouse
    draw_arrow(45, 29.5, 30, 36.5, color='#F43F5E', width=1.8, label="Alerts & Events (retried until committed)", label_pos=0.5)

    # ==================== TIER 5: INGESTION DAEMONS & WIRE GATEWAY (y: 22 to 29.5) ====================
    draw_card(3, 21.5, 94, 8.0, '#172554', '#2563EB', border_width=1.5, radius=1.5)
    ax.text(5, 28.3, "INGESTION DAEMONS & WIRE PROTOCOL GATEWAY", color='#93C5FD', fontsize=11, fontweight='bold', fontfamily='sans-serif')

    # Daemon 1: Wazuh Remoted
    draw_card(5, 22.3, 46, 5.2, '#1E3A8A', '#3B82F6', border_width=1.8, radius=0.8)
    draw_badge(20, 26.5, "WAZUH MANAGER: remoted :1514 -> analysisd -> wazuh-db", '#2563EB', fontsize=8.5)
    ax.text(6, 24.8, "Per-agent AES keys (client.keys)  •  rules & decoders  •  modulesd", color='#93C5FD', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    ax.text(6, 23.0, "alerts.json / archives.json = durable queue  •  scale out: N managers behind a TCP load balancer",
            color='#DBEAFE', fontsize=7.5, fontfamily='sans-serif')

    # Daemon 2: Syslog Ingestion Gateway
    draw_card(53, 22.3, 42, 5.2, '#312E81', '#6366F1', border_width=1.8, radius=0.8)
    draw_badge(69, 26.5, "SYSLOG: TLS :6514 (per-tenant certificates)  +  :514/:601", '#4F46E5', fontsize=8.5)
    ax.text(54, 24.8, "TLS: device client certificate -> tenant  •  revocable per device", color='#C7D2FE', fontsize=8, fontweight='bold', fontfamily='sans-serif')
    ax.text(54, 23.0, "Plain 514/601: private network / VPN only, source IP -> tenant map",
            color='#E0E7FF', fontsize=7.5, fontfamily='sans-serif')

    # Boundary separator
    ax.plot([3, 97], [19.5, 19.5], color='#EF4444', linestyle='--', lw=1.5, zorder=2)
    ax.text(50, 19.5, "  [ SECURED NETWORK BOUNDARY / FIREWALL ]  ", color='#F87171', fontsize=9,
            fontweight='bold', fontfamily='sans-serif', ha='center', va='center',
            bbox=dict(boxstyle='round,pad=0.2', facecolor='#0B1120', edgecolor='#EF4444', lw=1.0), zorder=4)

    # Connections crossing boundary
    draw_arrow(25, 14.5, 25, 21.5, color='#38BDF8', width=2.0, label="1514 (AES) + 443 (enroll, downloads)", label_pos=0.55, label_offset=(6, 0))
    draw_arrow(75, 14.5, 75, 21.5, color='#818CF8', width=1.8, label="6514 (TLS) / 514, 601 (private)", label_pos=0.55, label_offset=(-6, 0))

    # ==================== TIER 6: ENDPOINT AGENT FLEET & NETWORK SENSORS (y: 2 to 14.5) ====================
    draw_card(3, 1.5, 94, 13.0, '#042F2E', '#0D9488', border_width=2.0, radius=1.5)
    ax.text(5, 13.3, "DISTRIBUTED ENDPOINT AGENT FLEET & NETWORK SENSORS", color='#5EEAD4', fontsize=11, fontweight='bold', fontfamily='sans-serif')

    # Agent Card 1: Windows Agent (WazuhSvc)
    draw_card(5, 2.5, 28, 9.8, '#115E59', '#14B8A6', border_width=1.8, radius=1.0)
    draw_badge(18, 11.2, "WINDOWS AGENT (WazuhSvc)", '#0F766E', fontsize=8.5)
    ax.text(6, 9.6, "Process: wazuh-agent.exe", color='#99F6E4', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    win_details = (
        "• Location: Program Files (x86)\\ossec-agent\n"
        "• Windows EventLog (Sec, App, Sys)\n"
        "• Sysmon Event IDs 1-20 (Process, Net, DLL)\n"
        "• Syscollector (Specs, HW, Ports, Apps)\n"
        "• File & Registry Integrity Monitoring (FIM)\n"
        "• Active Response automated containment"
    )
    ax.text(6, 3.2, win_details, color='#CCFBF1', fontsize=7.8, fontfamily='sans-serif', linespacing=1.25)

    # Agent Card 2: Linux Endpoint Agent
    draw_card(35, 2.5, 28, 9.8, '#1E293B', '#38BDF8', border_width=1.8, radius=1.0)
    draw_badge(48, 11.2, "LINUX AGENT (siem-agent-linux)", '#0284C7', fontsize=8.5)
    ax.text(36, 9.6, "Systemd Daemon Service", color='#7DD3FC', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    linux_details = (
        "• Native lightweight Rust agent\n"
        "• Auditd kernel syscall monitor (execve)\n"
        "• Systemd journald & /var/log/secure\n"
        "• Center for Internet Security (CIS) SCA\n"
        "• Automated rootcheck & baseline auditing"
    )
    ax.text(36, 3.7, linux_details, color='#E0F2FE', fontsize=7.8, fontfamily='sans-serif', linespacing=1.25)

    # Agent Card 3: NDR Sensor & Appliances
    draw_card(65, 2.5, 30, 9.8, '#312E81', '#818CF8', border_width=1.8, radius=1.0)
    draw_badge(80, 11.2, "NDR SENSORS & APPLIANCES", '#4F46E5', fontsize=8.5)
    ax.text(66, 9.6, "Passive Sniffing & Syslog Streams", color='#C7D2FE', fontsize=8.5, fontweight='bold', fontfamily='sans-serif')
    net_details = (
        "• Passive SPAN/TAP Network Sensor\n"
        "• Zeek / Suricata deep packet inspection\n"
        "• JA4 TLS cryptographic fingerprinting\n"
        "• DNS tunneling & flow anomaly detection\n"
        "• Firewalls: FortiGate, Palo Alto, Cisco"
    )
    ax.text(66, 3.2, net_details, color='#EEF2FF', fontsize=7.8, fontfamily='sans-serif', linespacing=1.25)

    plt.tight_layout()
    plt.savefig(output_image_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f"Graphical diagram saved to: {output_image_path}")

if __name__ == "__main__":
    draw_architecture_diagram()
