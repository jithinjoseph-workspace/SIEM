import { Component, OnInit, ChangeDetectionStrategy, ViewChild, ElementRef, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { Api } from '../../../services/api/api';
import { ArkimeService } from '../../../services/arkime/arkime';
import {
    LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink, Plus,
    Trash2, Bell, Mail, Globe, Shield, Activity, ShieldAlert,
    Ban, ShieldOff, WifiOff, Wifi, AlertCircle
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';


import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
    selector: 'app-soar',
    standalone: true,
    imports: [CommonModule, LucideAngularModule, FormsModule],
    templateUrl: './soar.html',
    styleUrl: './soar.css',
    changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Soar implements OnInit {
    ZapIcon = Zap;
    PlayIcon = Play;
    PauseIcon = Pause;
    SettingsIcon = Settings;
    CheckIcon = CheckCircle;
    XIcon = XCircle;
    LinkIcon = Link;
    RefreshIcon = RefreshCw;
    ExternalIcon = ExternalLink;
    PlusIcon = Plus;
    TrashIcon = Trash2;
    BellIcon = Bell;
    MailIcon = Mail;
    GlobeIcon = Globe;
    ShieldIcon = Shield;
    ActivityIcon = Activity;
    ShieldAlertIcon = ShieldAlert;
    BanIcon = Ban;
    ShieldOffIcon = ShieldOff;
    WifiOffIcon = WifiOff;
    WifiIcon = Wifi;
    CheckCircleIcon = CheckCircle;
    AlertCircleIcon = AlertCircle;

    // ── Signals ───────────────────────────────────────────────────────────────
    activeTab = signal<'cases' | 'playbooks' | 'integrations' | 'activity' | 'blocks' | 'isolations'>('cases');
    loading   = signal(false);

    // Cases
    cases        = signal<any[]>([]);
    selectedCase = signal<any>(null);
    caseComments = signal<any[]>([]);
    loadingCase  = signal(false);

    // Playbooks
    playbooks    = signal<any[]>([]);
    showNewPlaybook = signal(false);
    savingPb     = signal(false);
    pbError      = signal('');

    // Integrations
    integrations     = signal<any[]>([]);
    showNewIntegration = signal(false);
    testingInt       = signal(false);
    testResult       = signal('');
    savingInt        = signal(false);
    testingAll       = signal(false);
    testAllResults   = signal<any[]>([]);

    // Activity
    runs = signal<any[]>([]);

    // Blocks
    activeBlocks  = signal<any[]>([]);
    loadingBlocks = signal(false);
    showBlockModal= signal(false);
    blockSaving   = signal(false);
    blockError    = signal('');

    // Isolations
    isolations        = signal<any[]>([]);
    loadingIsolations = signal(false);
    showIsolateModal  = signal(false);
    isolateSaving     = signal(false);
    isolateError      = signal('');

    // Isolation progress
    showIsolationProgress    = signal(false);
    isolationProgressTitle   = signal('');
    isolationProgressTarget  = signal('');
    isolationProgressSteps   = signal<{ label: string; status: 'pending' | 'running' | 'done' | 'error' }[]>([]);
    isolationProgressComplete = signal(false);
    isolationProgressSuccess  = signal(false);
    isolationProgressError    = signal('');

    // Evidence
    evidenceLoading      = signal(false);
    liveEvidence         = signal<any>(null);
    dismissedSessionIds  = signal(new Set<string>());
    collectingPcap       = signal(false);
    collectPcapDone      = signal(false);
    showEvidenceOverlay  = signal(false);
    evidenceOverlaySrc   = signal<SafeResourceUrl>('');
    selectedSession      = signal<any>(null);

    // Case close / resolve form
    showCloseForm    = signal(false);
    pendingStatus    = signal('');
    incidentReport   = signal<any>(null);
    showReportModal  = signal(false);

    // PCAP viewer
    pcapViewSession  = signal<any>(null);
    pcapPackets      = signal<any[]>([]);
    pcapLoading      = signal(false);
    pcapError        = signal('');
    showPcapAnalysis = signal(false);
    pcapAnalysis     = signal<any>(null);
    paActiveTab      = signal('overview');
    expandedPktIdx   = signal(new Set<number>());

    // New case form
    showNewCase    = signal(false);
    savingNewCase  = signal(false);
    newCaseError   = signal('');

    // Assignee inline edit
    editingAssignee = signal(false);

    // ── Plain properties (ngModel-bound form inputs) ───────────────────────────
    newComment        = '';
    sessionNote       = '';
    pcapNote          = '';
    closeNotes        = '';
    addToIntel        = true;
    intelGroup        = '';
    assigneeInput     = '';

    blockIp          = '';
    blockPort: number | null = null;
    blockDuration    = 24;
    blockEnforcement: 'rst' | 'firewall' | 'both' = 'both';
    blockReason      = '';

    isolateIp        = '';
    isolateGateway   = '192.168.1.1';
    isolateEnforcement: 'arp' | 'unifi' | 'cisco' | 'aruba' | 'snmp' | 'aws_sg' | 'azure_nsg' | 'gcp_vpc' = 'arp';
    isolateVlan      = 999;
    isolateReason    = '';

    pbName           = '';
    pbDesc           = '';
    pbCondField      = 'score';
    pbCondOp         = '>';
    pbCondValue      = '75';
    pbActionType     = 'slack';
    pbActionConfig: any = {};
    editingPbId: string | null = null;

    intType          = 'slack';
    intName          = '';
    intConfig: any   = {};
    editingIntId: string | null = null;

    newCaseTitle      = '';
    newCaseDescription = '';
    newCaseSeverity   = 'HIGH';
    newCasePriority   = 'P2';
    newCaseAssignedTo = '';
    newCaseSrcIp      = '';
    newCaseDstIp      = '';
    newCaseTags       = '';

    sensorIds: string[] = [];
    currentUsername   = '';

    @ViewChild('paChartCanvas') paChartCanvas?: ElementRef<HTMLCanvasElement>;

    // ── Computed ──────────────────────────────────────────────────────────────
    caseStats = computed(() => {
        const cases = this.cases();
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTs = Math.floor(today.getTime() / 1000);
        const active        = cases.filter(c => !['Closed', 'False Positive'].includes(c.status)).length;
        const inProgress    = cases.filter(c => c.status === 'In Progress').length;
        const resolvedToday = cases.filter(c =>
            c.status === 'Resolved' && c.closed_at && c.closed_at >= todayTs
        ).length;
        const closed = cases.filter(c =>
            ['Resolved', 'Closed'].includes(c.status) && c.closed_at && c.created_at
        );
        const avgHrs = closed.length
            ? Math.round(closed.reduce((s, c) => s + (c.closed_at - c.created_at) / 3600, 0) / closed.length)
            : 0;
        return { active, inProgress, resolvedToday, avgHrs };
    });

    visibleSessions = computed(() =>
        (this.liveEvidence()?.pcap_sessions || []).filter((s: any) => !this.dismissedSessionIds().has(s.id))
    );

    // ── Constants ─────────────────────────────────────────────────────────────
    isolationEnforcementTypes = [
        { value: 'arp',       label: 'ARP Spoofing (instant, agent-side)' },
        { value: 'unifi',     label: 'UniFi — Block Station (REST)' },
        { value: 'cisco',     label: 'Cisco IOS — VLAN quarantine (SNMP)' },
        { value: 'aruba',     label: 'Aruba CX — Access VLAN (REST)' },
        { value: 'snmp',      label: 'Generic Switch — VLAN quarantine (SNMP)' },
        { value: 'aws_sg',    label: 'AWS Security Group — revoke ingress' },
        { value: 'azure_nsg', label: 'Azure NSG — Deny inbound rule' },
        { value: 'gcp_vpc',   label: 'GCP VPC Firewall — Deny ingress rule' },
    ];

    integrationTypes = [
        { type: 'slack',     name: 'Slack',      abbr: 'SLK', group: 'notify',   fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...', type: 'text' }] },
        { type: 'teams',     name: 'MS Teams',   abbr: 'TMS', group: 'notify',   fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...', type: 'text' }] },
        { type: 'discord',   name: 'Discord',    abbr: 'DSC', group: 'notify',   fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/...', type: 'text' }] },
        { type: 'webhook',   name: 'Webhook',    abbr: 'WHK', group: 'notify',   fields: [{ key: 'webhook_url', label: 'Endpoint URL', placeholder: 'https://your-endpoint.com/alert', type: 'text' }] },
        { type: 'pagerduty', name: 'PagerDuty',  abbr: 'PDY', group: 'notify',   fields: [{ key: 'routing_key', label: 'Routing Key', placeholder: 'abc123...', type: 'password' }] },
        { type: 'telegram',  name: 'Telegram',   abbr: 'TGM', group: 'notify',   fields: [{ key: 'bot_token', label: 'Bot Token', placeholder: '123456:ABC-DEF...', type: 'password' }, { key: 'chat_id', label: 'Chat ID', placeholder: '-1001234567890', type: 'text' }] },
        { type: 'smtp',      name: 'Email',      abbr: 'EML', group: 'notify',   fields: [{ key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.gmail.com', type: 'text' }, { key: 'smtp_port', label: 'SMTP Port', placeholder: '587', type: 'text' }, { key: 'smtp_user', label: 'Username', placeholder: 'user@domain.com', type: 'text' }, { key: 'smtp_pass', label: 'Password', placeholder: '••••••••', type: 'password' }, { key: 'from_addr', label: 'From Address', placeholder: 'alerts@domain.com', type: 'text' }, { key: 'to_addr', label: 'Recipient', placeholder: 'soc@domain.com', type: 'text' }] },
        { type: 'pfsense',   name: 'pfSense',    abbr: 'PFS', group: 'firewall', fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }] },
        { type: 'fortinet',  name: 'FortiGate',  abbr: 'FGT', group: 'firewall', fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }, { key: 'vdom', label: 'VDOM', placeholder: 'root', type: 'text' }] },
        { type: 'panos',     name: 'PAN-OS',     abbr: 'PAN', group: 'firewall', fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }] },
        { type: 'opnsense',  name: 'OPNsense',   abbr: 'OPN', group: 'firewall', fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'Key:Secret', placeholder: 'key:secret', type: 'password' }] },
        { type: 'unifi',     name: 'UniFi',      abbr: 'UFI', group: 'switch',   fields: [{ key: 'host', label: 'Controller URL', placeholder: 'https://192.168.1.1:8443', type: 'text' }, { key: 'username', label: 'Username', placeholder: 'admin', type: 'text' }, { key: 'password', label: 'Password', placeholder: '••••••••', type: 'password' }, { key: 'site', label: 'Site', placeholder: 'default', type: 'text' }] },
        { type: 'cisco',     name: 'Cisco SNMP', abbr: 'CSC', group: 'switch',   fields: [{ key: 'host', label: 'Switch IP', placeholder: '192.168.1.2', type: 'text' }, { key: 'community', label: 'Write Community', placeholder: 'private', type: 'password' }, { key: 'port_ifindex', label: 'Port ifIndex', placeholder: '1', type: 'text' }] },
        { type: 'aruba',     name: 'Aruba CX',   abbr: 'ARB', group: 'switch',   fields: [{ key: 'host', label: 'Switch URL', placeholder: 'https://192.168.1.3', type: 'text' }, { key: 'username', label: 'Username', placeholder: 'admin', type: 'text' }, { key: 'password', label: 'Password', placeholder: '••••••••', type: 'password' }, { key: 'port', label: 'Port (e.g. 1/1/5)', placeholder: '1/1/5', type: 'text' }] },
        { type: 'snmp',      name: 'Generic SNMP', abbr: 'SNM', group: 'switch', fields: [{ key: 'host', label: 'Switch IP', placeholder: '192.168.1.4', type: 'text' }, { key: 'community', label: 'Write Community', placeholder: 'private', type: 'password' }, { key: 'port_ifindex', label: 'Port ifIndex', placeholder: '1', type: 'text' }] },
        { type: 'aws_sg',    name: 'AWS SG',     abbr: 'AWS', group: 'cloud',    fields: [{ key: 'sg_id', label: 'Security Group ID', placeholder: 'sg-0123456789abcdef', type: 'text' }, { key: 'region', label: 'Region', placeholder: 'us-east-1', type: 'text' }, { key: 'aws_access_key_id', label: 'Access Key ID', placeholder: 'AKIA...', type: 'text' }, { key: 'aws_secret_access_key', label: 'Secret Access Key', placeholder: '...', type: 'password' }] },
        { type: 'azure_nsg', name: 'Azure NSG',  abbr: 'AZR', group: 'cloud',    fields: [{ key: 'resource_group', label: 'Resource Group', placeholder: 'my-rg', type: 'text' }, { key: 'nsg_name', label: 'NSG Name', placeholder: 'my-nsg', type: 'text' }, { key: 'subscription_id', label: 'Subscription ID (optional)', placeholder: '...', type: 'text' }] },
        { type: 'gcp_vpc',   name: 'GCP VPC',    abbr: 'GCP', group: 'cloud',    fields: [{ key: 'project', label: 'Project ID', placeholder: 'my-project', type: 'text' }, { key: 'network', label: 'Network', placeholder: 'default', type: 'text' }] },
    ];

    readonly WORKFLOW_STATES = ['New', 'Assigned', 'In Progress', 'Pending', 'Under Review', 'Resolved', 'Closed'];
    readonly WORKFLOW_NEXT: Record<string, string[]> = {
        'New':                ['Assigned', 'In Progress', 'False Positive'],
        'Assigned':           ['In Progress', 'Pending', 'False Positive'],
        'In Progress':        ['Pending', 'Under Review', 'Resolved', 'False Positive'],
        'Pending':            ['In Progress', 'Resolved', 'Closed', 'False Positive'],
        'Under Review':       ['In Progress', 'Resolved', 'Closed', 'False Positive'],
        'Resolved':           ['Closed', 'In Progress'],
        'Closed':             ['New'],
        'False Positive':     ['New'],
        'Evidence Collected': ['In Progress', 'Resolved', 'Closed', 'False Positive'],
    };

    constructor(private api: Api, private arkime: ArkimeService, private auth: AuthService, private router: Router, private sanitizer: DomSanitizer) {}

    // ── Evidence overlay ──────────────────────────────────────────────────────
    viewEvidence(cid: string) {
        const c = this.selectedCase();
        let url = `/analyst/evidence?cid=${encodeURIComponent(cid)}`;
        if (c?.src_ip) url += `&src_ip=${encodeURIComponent(c.src_ip)}`;
        if (c?.dst_ip) url += `&dst_ip=${encodeURIComponent(c.dst_ip)}`;
        this.evidenceOverlaySrc.set(this.sanitizer.bypassSecurityTrustResourceUrl(url));
        this.showEvidenceOverlay.set(true);
    }

    closeEvidenceOverlay() {
        this.showEvidenceOverlay.set(false);
        this.evidenceOverlaySrc.set('');
    }

    dismissSession(sessionId: string) {
        this.dismissedSessionIds.update(s => { const ns = new Set(s); ns.add(sessionId); return ns; });
    }

    // ── Session detail ────────────────────────────────────────────────────────
    analyzeSession(session: any) {
        this.selectedSession.set(session);
        this.sessionNote = '';
    }

    closeSessionDetail() {
        this.selectedSession.set(null);
        this.sessionNote = '';
    }

    addSessionNote(session: any) {
        const c = this.selectedCase();
        if (!this.sessionNote.trim() || !c) return;
        const flow = `${session.src_ip}:${session.src_port} → ${session.dst_ip}:${session.dst_port}`;
        const proto = (session.proto || 'TCP').toUpperCase();
        const comment = `[SESSION NOTE — ${flow} ${proto}] ${this.sessionNote.trim()}`;
        this.api.addSoarCaseComment(c.id, comment).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.sessionNote = '';
                    this.openCase(c);
                }
            },
            error: reportRxjsError
        });
    }

    // ── PCAP viewer ───────────────────────────────────────────────────────────
    openPcapViewer(session: any) {
        this.pcapViewSession.set(session);
        this.pcapPackets.set([]);
        this.pcapError.set('');
        this.pcapNote = '';
        this.expandedPktIdx.set(new Set());
        this.pcapLoading.set(true);
        const id   = session.id || session.session_id;
        const node = session.sensor_host || '';
        this.arkime.fetchPcapRaw(id, node, session).subscribe({
            next: (buf: ArrayBuffer) => {
                this.pcapLoading.set(false);
                if (buf.byteLength === 0) {
                    this.pcapError.set('PCAP file is empty. The capture may not be stored yet.');
                    return;
                }
                const firstByte = new Uint8Array(buf)[0];
                if (firstByte === 0x7b || firstByte === 0x3c || firstByte === 0x50) {
                    try {
                        const text = new TextDecoder().decode(buf.slice(0, 512));
                        const parsed = JSON.parse(text);
                        this.pcapError.set(parsed.message || parsed.error || 'PCAP not available from server.');
                    } catch {
                        this.pcapError.set('No packet capture stored for this session. Use ↓ Download to try fetching from Arkime directly.');
                    }
                    return;
                }
                const v = new DataView(buf);
                const magic = v.getUint32(0, false);
                if (magic === 0x0a0d0d0a) {
                    this.pcapError.set('PCAP-NG format detected. Use ↓ Download to open in Wireshark.');
                    return;
                }
                const pkts = this.parsePcap(buf);
                if (!pkts.length) {
                    this.pcapError.set('Could not parse PCAP — unrecognised format. Use ↓ Download to open in Wireshark.');
                }
                this.pcapPackets.set(pkts);
            },
            error: (e: any) => {
                this.pcapLoading.set(false);
                const raw = e?.error ? (() => { try { return new TextDecoder().decode(e.error); } catch { return ''; } })() : '';
                if (e?.status === 404 || raw.toLowerCase().includes('not found') || raw.toLowerCase().includes('not available')) {
                    this.pcapError.set('No packet capture stored for this session. Use ↓ Download to try fetching from Arkime directly.');
                } else if (e?.status === 502) {
                    this.pcapError.set('Arkime is not running on this sensor — PCAP is unavailable. Start Arkime and try again.');
                } else {
                    this.pcapError.set(raw || e?.message || 'PCAP not available — no local capture and Arkime is not configured.');
                }
            }
        });
    }

    closePcapViewer() {
        this.pcapViewSession.set(null);
        this.pcapPackets.set([]);
        this.pcapNote = '';
    }

    togglePktExpand(idx: number) {
        this.expandedPktIdx.update(s => {
            const ns = new Set(s);
            if (ns.has(idx)) ns.delete(idx); else ns.add(idx);
            return ns;
        });
    }

    addPcapNote() {
        const c = this.selectedCase();
        if (!this.pcapNote.trim() || !c) return;
        const s = this.pcapViewSession();
        const flow = s ? `${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}` : '';
        const comment = `[PCAP ANALYSIS${flow ? ' — ' + flow : ''}] ${this.pcapNote.trim()}`;
        this.api.addSoarCaseComment(c.id, comment).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.pcapNote = '';
                    this.openCase(c);
                }
            },
            error: reportRxjsError
        });
    }

    // ── Binary PCAP parser ────────────────────────────────────────────────────
    private parsePcap(buf: ArrayBuffer): any[] {
        if (buf.byteLength < 24) return [];
        const v    = new DataView(buf);
        const magicBE = v.getUint32(0, false);
        const isLE = (magicBE === 0xd4c3b2a1 || magicBE === 0x4d3cb2a1);
        const linkType = v.getUint32(20, isLE);
        let off = 24;
        const pkts: any[] = [];
        let idx = 1;
        let t0Sec = 0, t0Usec = 0;
        while (off + 16 <= buf.byteLength) {
            const tsSec  = v.getUint32(off,     isLE);
            const tsUsec = v.getUint32(off + 4, isLE);
            const inclLen = v.getUint32(off + 8,  isLE);
            const origLen = v.getUint32(off + 12, isLE);
            off += 16;
            if (inclLen > buf.byteLength - off || inclLen > 65536) break;
            if (idx === 1) { t0Sec = tsSec; t0Usec = tsUsec; }
            const relUs = (tsSec - t0Sec) * 1_000_000 + (tsUsec - t0Usec);
            const relMs = relUs / 1000;
            const pktData = new Uint8Array(buf, off, inclLen);
            const pkt: any = { idx, ts: relMs, len: inclLen, orig_len: origLen };
            if (linkType === 1)   this.parseEthernet(pktData, pkt);
            else if (linkType === 101) this.parseIPv4(pktData, 0, pkt);
            pkt.hexLines = this.toHexLines(pktData);
            pkts.push(pkt);
            off += inclLen;
            idx++;
        }
        return pkts;
    }

    private parseEthernet(data: Uint8Array, pkt: any) {
        if (data.length < 14) return;
        pkt.dst_mac = Array.from(data.slice(0, 6)).map((b: number) => b.toString(16).padStart(2,'0')).join(':');
        pkt.src_mac = Array.from(data.slice(6, 12)).map((b: number) => b.toString(16).padStart(2,'0')).join(':');
        const et = (data[12] << 8) | data[13];
        if (et === 0x0800) this.parseIPv4(data, 14, pkt);
        else if (et === 0x0806) { pkt.proto = 'ARP'; pkt.info = 'ARP request/reply'; }
        else if (et === 0x86dd) { pkt.proto = 'IPv6'; pkt.info = 'IPv6'; }
        else { pkt.proto = `0x${et.toString(16)}`; pkt.info = `EtherType ${pkt.proto}`; }
    }

    private parseIPv4(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 20) return;
        const ihl = (data[off] & 0x0f) * 4;
        const proto = data[off + 9];
        pkt.src_ip = `${data[off+12]}.${data[off+13]}.${data[off+14]}.${data[off+15]}`;
        pkt.dst_ip = `${data[off+16]}.${data[off+17]}.${data[off+18]}.${data[off+19]}`;
        pkt.ttl    = data[off + 8];
        pkt.ipId   = (data[off+4] << 8) | data[off+5];
        const ipPayoff = off + ihl;
        if      (proto === 6)  this.parseTCP(data, ipPayoff, pkt);
        else if (proto === 17) this.parseUDP(data, ipPayoff, pkt);
        else if (proto === 1)  this.parseICMP(data, ipPayoff, pkt);
        else { pkt.proto = `IP/${proto}`; pkt.info = `${pkt.src_ip} → ${pkt.dst_ip}`; }
    }

    private parseICMP(data: Uint8Array, off: number, pkt: any) {
        pkt.proto = 'ICMP';
        if (data.length < off + 4) { pkt.info = 'ICMP'; return; }
        const type = data[off], code = data[off+1];
        const ICMP_TYPES: Record<number, string> = { 0:'Echo Reply',3:'Destination Unreachable',4:'Source Quench',5:'Redirect',8:'Echo Request',9:'Router Advertisement',10:'Router Solicitation',11:'Time Exceeded',12:'Parameter Problem',13:'Timestamp',14:'Timestamp Reply',30:'Traceroute' };
        const UNREACH_CODES: Record<number, string> = { 0:'Net Unreachable',1:'Host Unreachable',2:'Protocol Unreachable',3:'Port Unreachable',4:'Fragmentation Needed',9:'Net Admin Prohibited',10:'Host Admin Prohibited',13:'Communication Prohibited' };
        const typeName = ICMP_TYPES[type] || `Type ${type}`;
        const codeName = type === 3 ? (UNREACH_CODES[code] || `code ${code}`) : type === 11 ? (code === 0 ? 'TTL Exceeded in Transit' : 'Fragment Reassembly Exceeded') : type === 5 ? (['Net','Host','TOS+Net','TOS+Host'][code] || `code ${code}`) + ' Redirect' : '';
        pkt.info = codeName ? `${typeName} (${codeName})` : typeName;
        pkt.icmpDecoded = [{ k: 'Type', v: `${type} — ${typeName}` }, { k: 'Code', v: codeName || String(code) }];
        if ((type === 8 || type === 0) && data.length >= off + 8) {
            const id  = (data[off+4] << 8) | data[off+5];
            const seq = (data[off+6] << 8) | data[off+7];
            pkt.icmpDecoded.push({ k: 'Identifier', v: String(id) });
            pkt.icmpDecoded.push({ k: 'Sequence',   v: String(seq) });
            pkt.info = `${typeName}  id=${id}  seq=${seq}`;
        }
    }

    private parseTCP(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 20) return;
        pkt.proto = 'TCP';
        pkt.src_port = (data[off] << 8) | data[off+1];
        pkt.dst_port = (data[off+2] << 8) | data[off+3];
        const fl = data[off+13];
        const fs = [fl&0x02?'SYN':'', fl&0x10?'ACK':'', fl&0x01?'FIN':'', fl&0x04?'RST':'', fl&0x08?'PSH':''].filter(Boolean).join('+');
        pkt.flags = fs;
        const dOff = ((data[off+12] >> 4) * 4);
        const pl = data.slice(off + dOff);
        if (pl.length > 0) {
            const txt = new TextDecoder('utf-8', { fatal: false }).decode(pl.slice(0, 4096));
            if (/^(GET |POST |PUT |DELETE |HEAD |PATCH |OPTIONS |HTTP\/)/.test(txt)) {
                pkt.proto = 'HTTP';
                const lines = txt.split('\r\n');
                pkt.info = lines[0].slice(0, 100);
                pkt.httpFirstLine = lines[0];
                pkt.httpHeaders = [];
                let bodyStart = -1;
                for (let i = 1; i < lines.length; i++) {
                    if (lines[i] === '') { bodyStart = i + 1; break; }
                    const colon = lines[i].indexOf(':');
                    if (colon > 0) pkt.httpHeaders.push({ k: lines[i].slice(0, colon).trim(), v: lines[i].slice(colon + 1).trim() });
                }
                const ceHeader = pkt.httpHeaders.find((h: any) => h.k.toLowerCase() === 'content-encoding');
                const encoding = ceHeader?.v?.toLowerCase() || '';
                const clHeader = pkt.httpHeaders.find((h: any) => h.k.toLowerCase() === 'content-length');
                const bodyLen  = clHeader ? parseInt(clHeader.v, 10) : 0;
                if (bodyStart > 0) {
                    if (encoding === 'gzip' || encoding === 'deflate' || encoding === 'br') {
                        pkt.httpBodyNote = `Body is ${encoding}-compressed (${bodyLen ? bodyLen + ' bytes' : 'binary'}) — download PCAP and open in Wireshark to view decoded content.`;
                    } else if (bodyStart < lines.length) {
                        const body = lines.slice(bodyStart).join('\r\n').slice(0, 1024);
                        if (body.trim()) pkt.httpBody = body;
                    }
                }
            } else if (pl[0] === 0x16 && pl[1] === 0x03) {
                pkt.proto = 'TLS';
                const tlsTypes: Record<number,string> = {1:'ClientHello',2:'ServerHello',11:'Certificate',12:'ServerKeyExchange',14:'ServerHelloDone',16:'ClientKeyExchange',20:'ChangeCipherSpec'};
                const hsType = pl.length > 5 ? pl[5] : 0;
                const hsName = tlsTypes[hsType] || 'Handshake';
                pkt.info = `TLS ${hsName}`;
                pkt.tlsDecoded = [
                    { k: 'Record Type', v: 'Handshake (22)' },
                    { k: 'Version',     v: pl.length > 2 ? `TLS 1.${pl[2] === 1 ? '0' : pl[2] === 2 ? '1' : pl[2] === 3 ? '2' : '?'}` : '?' },
                    { k: 'Handshake',   v: hsName },
                ];
                if (hsType === 1 && pl.length > 43) {
                    try {
                        let i = 43;
                        const sessLen = pl[i++];
                        i += sessLen;
                        const ciphLen = (pl[i] << 8) | pl[i+1]; i += 2 + ciphLen;
                        const compLen = pl[i++]; i += compLen;
                        if (i + 2 < pl.length) {
                            const extTotal = (pl[i] << 8) | pl[i+1]; i += 2;
                            const extEnd = i + extTotal;
                            while (i + 4 < extEnd) {
                                const extType = (pl[i] << 8) | pl[i+1]; i += 2;
                                const extLen  = (pl[i] << 8) | pl[i+1]; i += 2;
                                if (extType === 0 && i + 5 < pl.length) {
                                    const nameLen = (pl[i+3] << 8) | pl[i+4];
                                    const sni = String.fromCharCode(...Array.from(pl.slice(i+5, i+5+nameLen)));
                                    pkt.tlsDecoded.push({ k: 'SNI (server name)', v: sni });
                                    pkt.info = `TLS ClientHello → ${sni}`;
                                    break;
                                }
                                i += extLen;
                            }
                        }
                    } catch (_) {}
                }
            }
        }
        if (!pkt.info) pkt.info = `${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port} [${fs || 'ACK'}]`;
    }

    private parseUDP(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 8) return;
        pkt.proto = 'UDP';
        pkt.src_port = (data[off] << 8) | data[off+1];
        pkt.dst_port = (data[off+2] << 8) | data[off+3];
        const pl = data.slice(off + 8);
        if (pkt.src_port === 53 || pkt.dst_port === 53) {
            pkt.proto = 'DNS';
            this.parseDNS(pl, pkt);
        } else if (pkt.src_port === 67 || pkt.dst_port === 67) {
            pkt.proto = 'DHCP'; pkt.info = 'DHCP';
        } else {
            pkt.info = `${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port}`;
        }
    }

    private parseDNS(data: Uint8Array, pkt: any) {
        if (data.length < 12) { pkt.info = 'DNS'; return; }
        const flags   = (data[2] << 8) | data[3];
        const isResp  = !!(flags & 0x8000);
        const qdCount = (data[4] << 8) | data[5];
        const anCount = (data[6] << 8) | data[7];
        const rcode   = flags & 0x000f;
        const rcodes: Record<number,string> = {0:'No Error',1:'Format Error',2:'Server Failure',3:'NXDOMAIN',5:'Refused'};
        const readName = (off: number): [string, number] => {
            const parts: string[] = [];
            let i = off, safety = 0;
            while (i < data.length && data[i] !== 0 && safety++ < 64) {
                if ((data[i] & 0xc0) === 0xc0) { const ptr = ((data[i] & 0x3f) << 8) | data[i+1]; parts.push(readName(ptr)[0]); i += 2; break; }
                const len = data[i++];
                parts.push(String.fromCharCode(...Array.from(data.slice(i, i+len)))); i += len;
            }
            return [parts.join('.'), i + 1];
        };
        const QTYPES: Record<number,string> = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY'};
        let qname = '', qtype = '';
        if (qdCount > 0 && data.length > 12) {
            const [name, end] = readName(12);
            qname = name;
            if (end + 1 < data.length) qtype = QTYPES[(data[end] << 8) | data[end+1]] || String((data[end] << 8) | data[end+1]);
        }
        if (isResp) {
            const status = rcodes[rcode] || `rcode=${rcode}`;
            pkt.info = `DNS Response: ${qname} [${status}]${anCount ? ` (${anCount} answer${anCount>1?'s':''})` : ''}`;
        } else {
            pkt.info = `DNS Query: ${qname}${qtype ? ' (' + qtype + ')' : ''}`;
        }
        pkt.dnsDecoded = [
            { k: 'Direction', v: isResp ? 'Response' : 'Query' },
            { k: 'Name',      v: qname || '—' },
            { k: 'Type',      v: qtype || '—' },
            { k: 'Questions', v: String(qdCount) },
            { k: 'Answers',   v: String(anCount) },
            ...(isResp ? [{ k: 'Status', v: rcodes[rcode] || `rcode=${rcode}` }] : []),
        ];
    }

    private toHexLines(data: Uint8Array): string[] {
        const lines: string[] = [];
        for (let i = 0; i < Math.min(data.length, 512); i += 16) {
            const chunk = Array.from(data.slice(i, i + 16));
            const hex   = chunk.map((b: number) => b.toString(16).padStart(2,'0')).join(' ').padEnd(47, ' ');
            const ascii = chunk.map((b: number) => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
            lines.push(`${i.toString(16).padStart(4,'0')}  ${hex}  ${ascii}`);
        }
        if (data.length > 512) lines.push(`      ... ${data.length - 512} more bytes`);
        return lines;
    }

    protoColor(proto: string): string {
        switch ((proto || '').toUpperCase()) {
            case 'HTTP':  return 'text-green-400';
            case 'TLS':   return 'text-blue-400';
            case 'DNS':   return 'text-yellow-400';
            case 'TCP':   return 'text-sky-400';
            case 'UDP':   return 'text-purple-400';
            case 'ICMP':  return 'text-orange-400';
            case 'ARP':   return 'text-pink-400';
            default:      return 'text-on-surface-variant';
        }
    }

    isKeyHeader(key: string): boolean {
        const important = ['host', 'content-type', 'user-agent', 'authorization', 'cookie', 'set-cookie', 'location', 'server', 'x-forwarded-for'];
        return important.includes((key || '').toLowerCase());
    }

    // ── PCAP Analysis ─────────────────────────────────────────────────────────
    openPcapAnalysis() {
        const pkts = this.pcapPackets();
        const totalBytes = pkts.reduce((s: number, p: any) => s + (p.len || 0), 0);
        const protocols: Record<string, number> = {};
        for (const p of pkts) { const proto = p.proto || 'Other'; protocols[proto] = (protocols[proto] || 0) + 1; }
        const connMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.src_ip || !p.dst_ip) continue;
            const [a, b] = [`${p.src_ip}:${p.src_port||''}`, `${p.dst_ip}:${p.dst_port||''}`];
            const key = a < b ? `${a}|${b}` : `${b}|${a}`;
            if (!connMap.has(key)) connMap.set(key, { src: `${p.src_ip}${p.src_port?':'+p.src_port:''}`, dst: `${p.dst_ip}${p.dst_port?':'+p.dst_port:''}`, proto: p.proto, pkts: 0, bytes: 0 });
            const c = connMap.get(key); c.pkts++; c.bytes += p.len || 0;
        }
        const connections = [...connMap.values()].sort((a: any, b: any) => b.bytes - a.bytes);
        const http: any[] = [];
        for (const p of pkts) {
            if (!p.httpFirstLine) continue;
            const host = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'host')?.v || '';
            const ct   = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'content-type')?.v || '';
            const ua   = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'user-agent')?.v || '';
            http.push({ line: p.httpFirstLine, host, ct, ua, src: p.src_ip, dst: p.dst_ip });
        }
        const dnsMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.dnsDecoded?.length) continue;
            const name = p.dnsDecoded.find((h: any) => h.k === 'Name')?.v || '—';
            const type = p.dnsDecoded.find((h: any) => h.k === 'Type')?.v || '';
            const dir  = p.dnsDecoded.find((h: any) => h.k === 'Direction')?.v || '';
            const stat = p.dnsDecoded.find((h: any) => h.k === 'Status')?.v || '';
            const key  = `${name}|${type}`;
            if (!dnsMap.has(key)) dnsMap.set(key, { name, type, status: stat, hasResp: dir === 'Response' });
            else if (dir === 'Response') { dnsMap.get(key).status = stat; dnsMap.get(key).hasResp = true; }
        }
        const dns = [...dnsMap.values()];
        const tlsMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.tlsDecoded?.length) continue;
            const sni = p.tlsDecoded.find((h: any) => h.k === 'SNI (server name)')?.v || '';
            const hs  = p.tlsDecoded.find((h: any) => h.k === 'Handshake')?.v || '';
            const ver = p.tlsDecoded.find((h: any) => h.k === 'Version')?.v || '';
            const key = sni || `${p.src_ip}→${p.dst_ip}`;
            if (!tlsMap.has(key)) tlsMap.set(key, { sni: sni || '(no SNI)', hs, ver, dst: p.dst_ip, count: 0 });
            tlsMap.get(key).count++;
        }
        const tls = [...tlsMap.values()];
        const icmp: any[] = [];
        for (const p of pkts) {
            if (!p.icmpDecoded?.length) continue;
            const typeV = p.icmpDecoded.find((h: any) => h.k === 'Type')?.v || '';
            const desc  = p.icmpDecoded.find((h: any) => h.k === 'Description')?.v || p.info || '';
            icmp.push({ desc, type: typeV, src: p.src_ip, dst: p.dst_ip });
        }
        this.pcapAnalysis.set({ totalPackets: pkts.length, totalBytes, protocols, connections, http, dns, tls, icmp });
        this.paActiveTab.set('overview');
        this.showPcapAnalysis.set(true);
        setTimeout(() => this.drawPcapChart(), 60);
    }

    setpaTab(tab: string) {
        this.paActiveTab.set(tab);
        if (tab === 'overview') setTimeout(() => this.drawPcapChart(), 60);
    }

    drawPcapChart() {
        const canvas = document.getElementById('pa-chart-canvas') as HTMLCanvasElement | null;
        const analysis = this.pcapAnalysis();
        if (!canvas || !analysis) return;
        const pkts = this.pcapPackets();
        if (!pkts.length) return;

        const dpr = window.devicePixelRatio || 1;
        const W = canvas.offsetWidth;
        const H = canvas.offsetHeight;
        canvas.width  = W * dpr;
        canvas.height = H * dpr;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.scale(dpr, dpr);

        const maxTs = pkts[pkts.length - 1]?.ts || 1;
        const BUCKETS = 60;
        const protos  = ['HTTP', 'TLS', 'DNS', 'ICMP', 'UDP', 'TCP', 'ARP', 'Other'];
        const colors: Record<string, string> = { HTTP:'#86efac', TLS:'#93c5fd', DNS:'#fcd34d', ICMP:'#fdba74', UDP:'#c4b5fd', TCP:'#38bdf8', ARP:'#f9a8d4', Other:'rgba(255,255,255,0.18)' };

        const data: Record<string, number[]> = {};
        for (const pr of protos) data[pr] = new Array(BUCKETS).fill(0);
        for (const p of pkts) {
            const bi = Math.min(Math.floor((p.ts / maxTs) * BUCKETS), BUCKETS - 1);
            const pr = protos.includes(p.proto) ? p.proto : 'Other';
            data[pr][bi] += p.len || 0;
        }

        let maxVal = 1;
        for (let i = 0; i < BUCKETS; i++) {
            const sum = protos.reduce((s, pr) => s + data[pr][i], 0);
            if (sum > maxVal) maxVal = sum;
        }

        const pad = { top: 16, right: 8, bottom: 24, left: 48 };
        const cW = W - pad.left - pad.right;
        const cH = H - pad.top - pad.bottom;
        const bw = cW / BUCKETS;

        ctx.clearRect(0, 0, W, H);
        ctx.strokeStyle = 'rgba(255,255,255,0.06)';
        ctx.lineWidth = 1;
        for (let g = 0; g <= 4; g++) {
            const y = pad.top + cH - (g / 4) * cH;
            ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cW, y); ctx.stroke();
        }

        const stackBottom = new Array(BUCKETS).fill(0);
        for (const pr of [...protos].reverse()) {
            ctx.beginPath();
            const points: [number,number][] = [];
            for (let i = 0; i < BUCKETS; i++) {
                const x = pad.left + i * bw + bw / 2;
                const stackH = (stackBottom[i] + data[pr][i]) / maxVal * cH;
                points.push([x, pad.top + cH - stackH]);
            }
            ctx.moveTo(points[0][0], points[0][1]);
            for (let i = 1; i < points.length - 1; i++) {
                const mx = (points[i][0] + points[i+1][0]) / 2;
                const my = (points[i][1] + points[i+1][1]) / 2;
                ctx.quadraticCurveTo(points[i][0], points[i][1], mx, my);
            }
            ctx.lineTo(points[points.length-1][0], points[points.length-1][1]);
            const baseY = pad.top + cH;
            ctx.lineTo(pad.left + cW, baseY);
            ctx.lineTo(pad.left, baseY);
            ctx.closePath();
            ctx.fillStyle = colors[pr] ? colors[pr].startsWith('#') ? colors[pr] + '55' : colors[pr].replace(')', ', 0.35)').replace('rgb', 'rgba') : 'rgba(255,255,255,0.1)';
            ctx.fill();
            for (let i = 0; i < BUCKETS; i++) stackBottom[i] += data[pr][i];
        }

        ctx.fillStyle = 'rgba(255,255,255,0.3)';
        ctx.font = `${9 * dpr / dpr}px monospace`;
        ctx.textAlign = 'right';
        for (let g = 0; g <= 4; g++) {
            const val = (g / 4) * maxVal;
            const y   = pad.top + cH - (g / 4) * cH;
            ctx.fillText(this.formatBytes(val), pad.left - 4, y + 3);
        }
        ctx.textAlign = 'center';
        const fmtMs = (ms: number) => ms < 1 ? `${(ms*1000).toFixed(0)}µs` : ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms/1000).toFixed(2)}s`;
        ctx.fillText('0ms', pad.left, H - 4);
        ctx.fillText(fmtMs(maxTs / 2), pad.left + cW / 2, H - 4);
        ctx.fillText(fmtMs(maxTs), pad.left + cW, H - 4);
    }

    protocolList(): { proto: string; count: number }[] {
        const analysis = this.pcapAnalysis();
        if (!analysis) return [];
        return Object.entries(analysis.protocols)
            .map(([proto, count]) => ({ proto, count: count as number }))
            .sort((a, b) => b.count - a.count);
    }

    formatBytes(b: number): string {
        if (b < 1024) return `${b} B`;
        if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
        return `${(b/1048576).toFixed(2)} MB`;
    }

    downloadPcap(session: any) {
        this.arkime.downloadPcap(session.id || session.session_id, session.sensor_host || '', session);
    }

    sessionDuration(s: any): string {
        if (!s.start_time || !s.end_time) return '—';
        const ms = s.end_time - s.start_time;
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    ngOnInit() {
        this.sensorIds = this.auth.getSensorIds();
        const user = this.auth.getUser();
        this.currentUsername = user?.username || user?.name || '';
        this.loadCases();
        this.loadPlaybooks();
        this.loadIntegrations();
        this.loadRuns();
    }

    // ── Data loaders ──────────────────────────────────────────────────────────
    loadCases() {
        this.api.getSoarCases().subscribe({
            next: (res: any) => { if (res.status === 'success') this.cases.set(res.data); },
            error: reportRxjsError
        });
    }

    loadPlaybooks() {
        this.api.getNativePlaybooks().subscribe({
            next: (res: any) => { if (res.status === 'success') this.playbooks.set(res.data); },
            error: reportRxjsError
        });
    }

    loadIntegrations() {
        this.api.getIntegrations().subscribe({
            next: (res: any) => { this.integrations.set(res.integrations || []); },
            error: reportRxjsError
        });
    }

    loadRuns() {
        this.api.getSoarRuns().subscribe({
            next: (res: any) => { if (res.status === 'success') this.runs.set(res.data); },
            error: reportRxjsError
        });
    }

    // ── Tab switching ─────────────────────────────────────────────────────────
    switchTab(tab: 'cases' | 'playbooks' | 'integrations' | 'activity' | 'blocks' | 'isolations') {
        this.activeTab.set(tab);
        if (tab === 'cases')        this.loadCases();
        if (tab === 'playbooks')    this.loadPlaybooks();
        if (tab === 'integrations') this.loadIntegrations();
        if (tab === 'activity')     this.loadRuns();
        if (tab === 'blocks')       this.loadBlocks();
        if (tab === 'isolations')   this.loadIsolations();
    }

    // ── Blocks ────────────────────────────────────────────────────────────────
    loadBlocks() {
        this.loadingBlocks.set(true);
        this.api.listActiveBlocks().subscribe({
            next: (res: any) => { this.activeBlocks.set(res.data || []); this.loadingBlocks.set(false); },
            error: () => this.loadingBlocks.set(false),
        });
    }

    revokeBlock(b: any) {
        if (!confirm(`Revoke block on ${b.src_ip}?`)) return;
        this.api.revokeBlock(b.id, b.sensor_id || undefined).subscribe({
            next: () => this.loadBlocks(),
            error: () => alert('Failed to revoke block'),
        });
    }

    openBlockModal() {
        this.blockIp = '';
        this.blockPort = null;
        this.blockDuration = 24;
        this.blockEnforcement = 'both';
        this.blockReason = '';
        this.blockError.set('');
        this.showBlockModal.set(true);
    }

    submitManualBlock() {
        if (!this.blockIp.trim()) { this.blockError.set('IP address is required'); return; }
        this.blockSaving.set(true);
        this.blockError.set('');
        this.api.manualBlock({
            src_ip:         this.blockIp.trim(),
            src_port:       this.blockPort ?? undefined,
            duration_hours: this.blockDuration,
            enforcement:    this.blockEnforcement,
            reason:         this.blockReason || undefined,
        }).subscribe({
            next: (res: any) => {
                this.blockSaving.set(false);
                if (res.status === 'success') { this.showBlockModal.set(false); this.loadBlocks(); }
                else this.blockError.set(res.message || 'Block failed');
            },
            error: (err: any) => { this.blockSaving.set(false); this.blockError.set(err.error?.message || 'Request failed'); },
        });
    }

    // ── Isolations ────────────────────────────────────────────────────────────
    loadIsolations() {
        this.loadingIsolations.set(true);
        this.api.listIsolations().subscribe({
            next: (res: any) => { this.isolations.set(res.data || []); this.loadingIsolations.set(false); },
            error: () => this.loadingIsolations.set(false),
        });
    }

    openIsolateModal() {
        this.isolateIp = '';
        this.isolateGateway = '';
        this.isolateEnforcement = 'arp';
        this.isolateVlan = 999;
        this.isolateReason = '';
        this.isolateError.set('');
        this.showIsolateModal.set(true);
        this.api.getAgentStatus().subscribe({
            next: (s: any) => { if (s?.gateway) this.isolateGateway = s.gateway; },
            error: reportRxjsError,
        });
    }

    private startIsolationProgress(title: string, target: string, steps: string[]) {
        this.isolationProgressTitle.set(title);
        this.isolationProgressTarget.set(target);
        this.isolationProgressSteps.set(steps.map(label => ({ label, status: 'pending' as const })));
        this.isolationProgressComplete.set(false);
        this.isolationProgressSuccess.set(false);
        this.isolationProgressError.set('');
        this.showIsolationProgress.set(true);
    }

    private async runIsolationSteps(apiCall: Promise<any>, stepDelays: number[]) {
        const advance = (idx: number) => {
            this.isolationProgressSteps.update(steps => {
                const s = steps.map((st, i) => i === idx - 1 ? { ...st, status: 'done' as const } : i === idx ? { ...st, status: 'running' as const } : st);
                return s;
            });
        };
        advance(0);
        const timers: ReturnType<typeof setTimeout>[] = [];
        const totalSteps = this.isolationProgressSteps().length;
        for (let i = 1; i < totalSteps - 1; i++) {
            const delay = stepDelays[i - 1] ?? (i * 900);
            timers.push(setTimeout(() => advance(i), delay));
        }
        try {
            const res = await apiCall;
            timers.forEach(t => clearTimeout(t));
            this.isolationProgressSteps.update(s => s.map(st => ({ ...st, status: 'done' as const })));
            this.isolationProgressComplete.set(true);
            this.isolationProgressSuccess.set(true);
            if (res?.status !== 'success' && res?.message) {
                this.isolationProgressSteps.update(s => { const ns = [...s]; ns[ns.length - 1] = { ...ns[ns.length - 1], status: 'error' }; return ns; });
                this.isolationProgressSuccess.set(false);
                this.isolationProgressError.set(res.message);
            }
        } catch (err: any) {
            timers.forEach(t => clearTimeout(t));
            this.isolationProgressSteps.update(s => {
                const idx = s.findIndex(st => st.status === 'running');
                if (idx < 0) return s;
                return s.map((st, i) => i === idx ? { ...st, status: 'error' as const } : st);
            });
            this.isolationProgressComplete.set(true);
            this.isolationProgressSuccess.set(false);
            this.isolationProgressError.set(err?.error?.message || err?.message || 'Request failed');
        }
        this.loadIsolations();
    }

    submitIsolation() {
        if (!this.isolateIp.trim()) { this.isolateError.set('IP address is required'); return; }
        const ip = this.isolateIp.trim();
        const enforcement = this.isolateEnforcement;
        this.showIsolateModal.set(false);
        const isArp = enforcement === 'arp';
        const steps = isArp
            ? ['Connecting to sensor agent', 'Starting ARP poisoning', 'Applying iptables firewall rules', 'Confirming device isolation']
            : ['Connecting to sensor agent', `Sending ${enforcement.toUpperCase()} quarantine command`, 'Waiting for enforcement confirmation', 'Confirming device isolation'];
        this.startIsolationProgress('Isolating Device', ip, steps);
        const apiPromise = new Promise<any>((resolve, reject) => {
            this.api.isolateDevice({ target_ip: ip, gateway_ip: this.isolateGateway || undefined, enforcement, quarantine_vlan: this.isolateVlan, reason: this.isolateReason || undefined })
                .subscribe({ next: resolve, error: reject });
        });
        this.runIsolationSteps(apiPromise, [800, 1800, 2800]);
    }

    restoreIsolation(iso: any) {
        const enforcement = iso.enforcement || 'arp';
        const isArp = enforcement === 'arp';
        const steps = isArp
            ? ['Connecting to sensor agent', 'Stopping ARP poisoning', 'Removing iptables firewall rules', 'Network access restored']
            : ['Connecting to sensor agent', `Reverting ${enforcement.toUpperCase()} quarantine`, 'Waiting for enforcement rollback', 'Network access restored'];
        this.startIsolationProgress('Restoring Device', iso.target_ip, steps);
        const apiPromise = new Promise<any>((resolve, reject) => {
            this.api.unisolateDevice(iso.id).subscribe({ next: resolve, error: reject });
        });
        this.runIsolationSteps(apiPromise, [800, 1800, 2800]);
    }

    closeIsolationProgress() {
        this.showIsolationProgress.set(false);
    }

    isolationMethodLabel(enforcement: string): string {
        return this.isolationEnforcementTypes.find(t => t.value === enforcement)?.label.split(' — ')[0] || enforcement;
    }

    // ── Workflow helpers ──────────────────────────────────────────────────────
    nextStates(status: string): string[] {
        return this.WORKFLOW_NEXT[status] || ['In Progress'];
    }

    statusClass(status: string): string {
        switch (status) {
            case 'New':           return 'status-new';
            case 'Assigned':      return 'status-assigned';
            case 'In Progress':   return 'status-inprogress';
            case 'Pending':       return 'status-pending';
            case 'Under Review':  return 'status-review';
            case 'Resolved':      return 'status-resolved';
            case 'Closed':        return 'status-closed';
            case 'False Positive':return 'status-fp';
            default:              return 'status-inprogress';
        }
    }

    priorityClass(p: string): string {
        switch (p) {
            case 'P1': return 'prio-p1';
            case 'P2': return 'prio-p2';
            case 'P3': return 'prio-p3';
            default:   return 'prio-p4';
        }
    }

    severityClass(sev: string): string {
        switch ((sev || '').toUpperCase()) {
            case 'CRITICAL': return 'sev-critical';
            case 'HIGH':     return 'sev-high';
            case 'MEDIUM':   return 'sev-medium';
            case 'LOW':      return 'sev-low';
            default:         return 'sev-low';
        }
    }

    getCaseColor(severity: string) {
        const s = (severity || '').toLowerCase();
        if (s === 'critical') return 'text-red-400 bg-red-500/10';
        if (s === 'high') return 'text-orange-400 bg-orange-500/10';
        if (s === 'medium') return 'text-yellow-400 bg-yellow-500/10';
        return 'text-blue-400 bg-blue-500/10';
    }

    // ── New case form ─────────────────────────────────────────────────────────
    openNewCaseModal() {
        this.newCaseTitle = '';
        this.newCaseDescription = '';
        this.newCaseSeverity = 'HIGH';
        this.newCasePriority = 'P2';
        this.newCaseAssignedTo = this.currentUsername;
        this.newCaseSrcIp = '';
        this.newCaseDstIp = '';
        this.newCaseTags = '';
        this.newCaseError.set('');
        this.showNewCase.set(true);
    }

    submitNewCase() {
        if (!this.newCaseTitle.trim()) { this.newCaseError.set('Title is required'); return; }
        this.savingNewCase.set(true);
        this.newCaseError.set('');
        const tags = this.newCaseTags.split(',').map(t => t.trim()).filter(Boolean);
        this.api.createSoarCase({
            title: this.newCaseTitle.trim(), description: this.newCaseDescription.trim(),
            severity: this.newCaseSeverity, priority: this.newCasePriority,
            assigned_to: this.newCaseAssignedTo.trim(),
            src_ip: this.newCaseSrcIp.trim(), dst_ip: this.newCaseDstIp.trim(), tags,
        }).subscribe({
            next: (res: any) => {
                this.savingNewCase.set(false);
                if (res.status === 'success') { this.showNewCase.set(false); this.loadCases(); }
                else this.newCaseError.set(res.message || 'Failed to create case');
            },
            error: (err: any) => { this.savingNewCase.set(false); this.newCaseError.set(err.error?.message || 'Request failed'); },
        });
    }

    // ── Assignee inline edit ──────────────────────────────────────────────────
    startEditAssignee() {
        this.assigneeInput = this.selectedCase()?.assigned_to || this.currentUsername;
        this.editingAssignee.set(true);
    }

    saveAssignee() {
        const c = this.selectedCase();
        if (!c) return;
        this.editingAssignee.set(false);
        const assigned_to = this.assigneeInput.trim();
        this.api.updateSoarCase(c.id, {
            title: c.title, description: c.description,
            assigned_to, priority: c.priority || 'P2', severity: c.severity || 'MEDIUM',
        }).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.selectedCase.update(sc => sc ? { ...sc, assigned_to } : sc);
                    this.loadCases();
                }
            },
            error: reportRxjsError,
        });
    }

    // ── Cases logic ───────────────────────────────────────────────────────────
    openCase(c: any) {
        this.selectedCase.set(c);
        this.editingAssignee.set(false);
        this.liveEvidence.set(null);
        this.loadingCase.set(true);
        this.collectingPcap.set(false);
        this.collectPcapDone.set(false);
        this.pcapViewSession.set(null);
        this.pcapPackets.set([]);
        this.pcapError.set('');
        this.pcapLoading.set(false);
        this.pcapNote = '';
        this.selectedSession.set(null);
        this.sessionNote = '';
        this.expandedPktIdx.set(new Set());
        this.incidentReport.set(null);
        this.showCloseForm.set(false);

        this.api.getSoarCaseComments(c.id).subscribe({
            next: (res: any) => {
                if (res.status === 'success') this.caseComments.set(res.data);
                this.loadingCase.set(false);
            },
            error: () => { this.loadingCase.set(false); }
        });

        this.dismissedSessionIds.set(new Set());
        const hasPair = c.src_ip && c.dst_ip;
        const hasCid  = !!c.community_id;
        if (hasPair || hasCid) {
            this.evidenceLoading.set(true);
            const pcapParams = hasPair
                ? { src_ip: c.src_ip, dst_ip: c.dst_ip, limit: 50 }
                : { cid: c.community_id, limit: 50 };
            this.arkime.getSessions(pcapParams).subscribe({
                next: (pcap: any) => {
                    this.liveEvidence.update(ev => ({ ...(ev || {}), pcap_sessions: pcap.sessions || [], pcap_total: pcap.total || pcap.sessions?.length || 0 }));
                    this.evidenceLoading.set(false);
                },
                error: () => { this.evidenceLoading.set(false); }
            });
            if (hasCid) {
                this.api.getEventsByCid(c.community_id).subscribe({
                    next: (res: any) => {
                        this.liveEvidence.update(ev => ({ ...(ev || {}), ndr_events: res.events || [] }));
                    },
                    error: reportRxjsError
                });
            }
        }
    }

    closeCaseModal() {
        this.selectedCase.set(null);
        this.caseComments.set([]);
        this.liveEvidence.set(null);
        this.evidenceLoading.set(false);
        this.editingAssignee.set(false);
        this.collectingPcap.set(false);
        this.collectPcapDone.set(false);
        this.pcapViewSession.set(null);
        this.pcapPackets.set([]);
        this.pcapError.set('');
        this.pcapLoading.set(false);
        this.pcapNote = '';
        this.selectedSession.set(null);
        this.sessionNote = '';
        this.expandedPktIdx.set(new Set());
        this.incidentReport.set(null);
        this.showCloseForm.set(false);
    }

    updateCaseStatus(status: string) {
        const c = this.selectedCase();
        if (!c) return;
        if (['Resolved', 'Closed'].includes(status)) {
            this.pendingStatus.set(status);
            this.closeNotes = '';
            this.addToIntel = !!c.src_ip;
            this.intelGroup = (c.tags || []).join(', ');
            this.showCloseForm.set(true);
            return;
        }
        if (status === 'Assigned' && !c.assigned_to && this.currentUsername) {
            this.assigneeInput = this.currentUsername;
            this.saveAssignee();
        }
        this._doUpdateStatus(status);
    }

    private _resolutionFromComments(c: any): string {
        const comments = this.caseComments();
        if (comments?.length) {
            // Prefer the last [Closed] / [Resolved] / [False Positive] comment
            const closing = [...comments]
                .reverse()
                .find((cm: any) => /^\[(Closed|Resolved|False Positive)\]/i.test(cm.text || cm.comment || ''));
            if (closing) {
                const txt = closing.text || closing.comment || '';
                return txt.replace(/^\[.*?\]\s*/i, '').trim() || txt;
            }
            // Fall back to last analyst comment
            const last = [...comments].reverse().find((cm: any) => cm.author !== 'system' && cm.author !== 'SYSTEM');
            if (last) return last.text || last.comment || '';
        }
        return c.resolution || 'No resolution notes provided.';
    }

    openCaseReport() {
        const c = this.selectedCase();
        if (!c) return;
        // Always rebuild from case data so resolution pulls current comments
        this.incidentReport.set(null);
        if (!this.incidentReport()) {
            this.incidentReport.set({
                case_number: c.case_number,
                title:       c.title,
                severity:    c.severity,
                priority:    c.priority,
                src_ip:      c.src_ip,
                dst_ip:      c.dst_ip,
                status:      c.status,
                analyst:     c.assigned_to || this.currentUsername,
                closed_at:   c.closed_at
                    ? new Date(c.closed_at * 1000).toLocaleString()
                    : new Date().toLocaleString(),
                resolution:  this._resolutionFromComments(c),
                pcap_count:  this.liveEvidence()?.pcap_sessions?.length || 0,
                tags:        (c.tags || []).join(', '),
                description: c.description,
                intel_added: null,
            });
        }
        this.showReportModal.set(true);
    }

    confirmClose() {
        const c = this.selectedCase();
        if (!c) return;
        this._doUpdateStatus(this.pendingStatus());
        if (this.addToIntel && c.src_ip) {
            this.api.addManualIoc('ip', c.src_ip, this.intelGroup).subscribe();
        }
        this.incidentReport.set({
            case_number:  c.case_number,
            title:        c.title,
            severity:     c.severity,
            priority:     c.priority,
            src_ip:       c.src_ip,
            dst_ip:       c.dst_ip,
            status:       this.pendingStatus(),
            analyst:      this.currentUsername,
            closed_at:    new Date().toLocaleString(),
            resolution:   this.closeNotes || 'No notes provided.',
            pcap_count:   this.liveEvidence()?.pcap_sessions?.length || 0,
            tags:         (c.tags || []).join(', '),
            description:  c.description,
            intel_added:  this.addToIntel && c.src_ip ? `${c.src_ip} added to threat intel watchlist` : null,
        });
        if (this.closeNotes.trim()) {
            this.api.addSoarCaseComment(c.id, `[${this.pendingStatus()}] ${this.closeNotes}`).subscribe();
        }
        this.showCloseForm.set(false);
        this.showReportModal.set(true);
    }

    downloadReport(format: 'html' | 'pdf') {
        const r = this.incidentReport();
        if (!r) return;
        const html = this._buildReportHtml(r);
        const blob = new Blob([html], { type: 'text/html; charset=utf-8' });
        if (format === 'html') {
            const url = URL.createObjectURL(blob);
            const a   = document.createElement('a');
            a.href    = url;
            a.download = `incident-report-${r.case_number}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } else {
            // Open blob URL — suppresses localhost URL in print header
            const blobUrl = URL.createObjectURL(blob);
            const win = window.open(blobUrl, '_blank');
            if (win) {
                win.addEventListener('load', () => {
                    setTimeout(() => {
                        win.print();
                        setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
                    }, 400);
                });
            }
        }
    }

    private _buildReportHtml(r: any): string {  // eslint-disable-line
        const sessions  = this.liveEvidence()?.pcap_sessions || [];
        const events    = this.liveEvidence()?.ndr_events    || [];

        // ── Helpers ────────────────────────────────────────────────────
        const fmtBytes = (b: number): string => {
            if (!b) return '0 B';
            if (b > 1048576) return (b / 1048576).toFixed(2) + ' MB';
            if (b > 1024)    return (b / 1024).toFixed(1)    + ' KB';
            return b + ' B';
        };
        const fmtTs = (ts: any): string => {
            if (!ts) return '—';
            try {
                const ms = Number(ts);
                const d  = ms > 1e12 ? new Date(ms) : new Date(ms * 1000);
                return d.toLocaleString();
            } catch { return String(ts); }
        };

        // ── Traffic stats ──────────────────────────────────────────────
        const protoCounts: Record<string, number> = {};
        const protoBytes:  Record<string, number> = {};
        let totalBytes = 0, totalPackets = 0;
        const srcIps = new Set<string>(), dstIps = new Set<string>();
        for (const s of sessions) {
            const p = (s.proto || 'other').toUpperCase();
            protoCounts[p]  = (protoCounts[p]  || 0) + 1;
            protoBytes[p]   = (protoBytes[p]   || 0) + (Number(s.bytes) || 0);
            totalBytes   += Number(s.bytes)   || 0;
            totalPackets += Number(s.packets) || 0;
            if (s.src_ip) srcIps.add(s.src_ip);
            if (s.dst_ip) dstIps.add(s.dst_ip);
        }

        const protoColors: Record<string, string> = {
            TCP: '#2563eb', UDP: '#059669', ICMP: '#d97706',
            OTHER: '#7c3aed', HTTP: '#dc2626', HTTPS: '#0891b2', CONN: '#0284c7'
        };

        // ── Chart 1: Protocol session count (horizontal bars) ──────────
        const protoEntries = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);
        const maxCnt = Math.max(...protoEntries.map(e => e[1]), 1);
        const BH = 22, BG = 9;
        const c1H = protoEntries.length * (BH + BG) + 20;
        const c1Bars = protoEntries.map(([proto, cnt], i) => {
            const y   = 10 + i * (BH + BG);
            const w   = Math.max(4, Math.round((cnt / maxCnt) * 200));
            const pct = sessions.length ? Math.round((cnt / sessions.length) * 100) : 0;
            const col = protoColors[proto] || '#64748b';
            return `<g><text x="52" y="${y+15}" text-anchor="end" font-size="10" fill="#555" font-family="Arial">${proto}</text><rect x="58" y="${y}" width="${w}" height="${BH}" rx="2" fill="${col}"/><text x="${58+w+5}" y="${y+15}" font-size="10" fill="#222" font-family="Arial">${cnt} · ${pct}%</text></g>`;
        }).join('');

        // ── Chart 2: Protocol by bytes (horizontal bars) ───────────────
        const pbEntries = Object.entries(protoBytes).sort((a, b) => b[1] - a[1]);
        const maxPB = Math.max(...pbEntries.map(e => e[1]), 1);
        const c2H = pbEntries.length * (BH + BG) + 20;
        const c2Bars = pbEntries.map(([proto, bytes], i) => {
            const y   = 10 + i * (BH + BG);
            const w   = Math.max(4, Math.round((bytes / maxPB) * 200));
            const col = protoColors[proto] || '#64748b';
            return `<g><text x="52" y="${y+15}" text-anchor="end" font-size="10" fill="#555" font-family="Arial">${proto}</text><rect x="58" y="${y}" width="${w}" height="${BH}" rx="2" fill="${col}"/><text x="${58+w+5}" y="${y+15}" font-size="10" fill="#222" font-family="Arial">${fmtBytes(bytes)}</text></g>`;
        }).join('');

        // ── Chart 3: Top sessions by bytes ─────────────────────────────
        const topSess = [...sessions].sort((a: any, b: any) => (Number(b.bytes) || 0) - (Number(a.bytes) || 0)).slice(0, 8);
        const maxTopB = Math.max(...topSess.map((s: any) => Number(s.bytes) || 0), 1);
        const tBH = 18, tBG = 8;
        const c3H = topSess.length * (tBH + tBG) + 20;
        // Label: "192.168.1.70:3702 → 192.168.1.76:36964" needs ~38 monospace chars × ~5.5px = ~210px right-aligned
        const c3Bars = topSess.map((s: any, i: number) => {
            const y   = 10 + i * (tBH + tBG);
            const b   = Number(s.bytes) || 0;
            const w   = Math.max(4, Math.round((b / maxTopB) * 140));
            const lbl = `${s.src_ip || '?'}:${s.src_port || ''} → ${s.dst_ip || '?'}:${s.dst_port || ''}`;
            const barX = 230;
            return `<g><text x="${barX-5}" y="${y+13}" text-anchor="end" font-size="8.5" fill="#334155" font-family="'Courier New',monospace">${lbl}</text><rect x="${barX}" y="${y}" width="${w}" height="${tBH}" rx="2" fill="#2563eb" opacity="0.82"/><text x="${barX+w+5}" y="${y+13}" font-size="9" fill="#0f172a" font-family="Arial,sans-serif" font-weight="600">${fmtBytes(b)}</text></g>`;
        }).join('');

        // ── Chart 4: Session timeline (sessions per time bucket) ────────
        let timelineHtml = '';
        const sortedTs = sessions
            .map((s: any) => Number(s.start_time))
            .filter((t: number) => t > 0)
            .sort((a: number, b: number) => a - b);
        if (sortedTs.length > 1) {
            const minT = sortedTs[0], maxT = sortedTs[sortedTs.length - 1];
            const span = maxT - minT || 1;
            const buckets = 18;
            const bkSize  = span / buckets;
            const cnts    = new Array(buckets).fill(0);
            sortedTs.forEach((t: number) => {
                const idx = Math.min(buckets - 1, Math.floor((t - minT) / bkSize));
                cnts[idx]++;
            });
            const maxBkt = Math.max(...cnts, 1);
            const tlW = 440, tlH = 70;
            const bw = Math.floor(tlW / buckets) - 1;
            const tlBars = cnts.map((cnt: number, i: number) => {
                const bh  = Math.max(2, Math.round((cnt / maxBkt) * (tlH - 18)));
                const x   = i * (bw + 1);
                const y   = tlH - bh - 14;
                const col = cnt > 0 ? '#2563eb' : '#e2e8f0';
                // Count label above bar (never overlapping the bottom axis)
                const lblY = Math.max(8, y - 3);
                const lbl  = cnt > 0 ? `<text x="${x+bw/2}" y="${lblY}" text-anchor="middle" font-size="7" fill="#2563eb" font-family="Arial">${cnt}</text>` : '';
                return `<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="1" fill="${col}" opacity="0.8"/>${lbl}`;
            }).join('');
            const lbl0 = new Date(minT > 1e12 ? minT : minT*1000).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
            const lbl1 = new Date(maxT > 1e12 ? maxT : maxT*1000).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
            const tlDate = new Date(minT > 1e12 ? minT : minT*1000).toLocaleDateString();
            timelineHtml = `<div class="chart-lbl">Session Timeline — ${tlDate} (${sortedTs.length} sessions)</div>
<div class="chart-box" style="padding:12px 14px 8px">
<svg width="100%" viewBox="0 0 ${tlW} ${tlH+4}" xmlns="http://www.w3.org/2000/svg">
${tlBars}
<line x1="0" y1="${tlH-14}" x2="${tlW}" y2="${tlH-14}" stroke="#e2e8f0" stroke-width="1"/>
<text x="0" y="${tlH+2}" font-size="7.5" fill="#94a3b8" font-family="Arial">${lbl0}</text>
<text x="${tlW}" y="${tlH+2}" text-anchor="end" font-size="7.5" fill="#94a3b8" font-family="Arial">${lbl1}</text>
</svg>
</div>`;
        }

        // ── Session rows (ALL sessions) ─────────────────────────────────
        const sessRows = sessions.map((s: any) => `<tr>
<td>${fmtTs(s.start_time)}</td>
<td>${s.src_ip || '—'}:${s.src_port || ''}</td>
<td>${s.dst_ip || '—'}:${s.dst_port || ''}</td>
<td><b>${(s.proto || '—').toUpperCase()}</b></td>
<td style="text-align:right">${fmtBytes(Number(s.bytes))}</td>
<td style="text-align:right">${s.packets || 0}</td>
</tr>`).join('');

        // ── NDR event rows ─────────────────────────────────────────────
        const eventRows = events.map((e: any) => `<tr>
<td>${e.ts || e.timestamp || '—'}</td>
<td><b>${e.event_type || e.type || '—'}</b></td>
<td>${e.src_ip || '—'}</td>
<td>${e.dst_ip || '—'}</td>
<td>${e.note || e.message || '—'}</td>
</tr>`).join('');

        // ── Auto executive summary ─────────────────────────────────────
        const sevLow   = (r.severity || 'unknown').toLowerCase();
        const tag1     = (r.tags || '').split(',')[0]?.trim() || 'network threat';
        const execSum  = `A ${sevLow}-severity ${tag1} incident (${r.case_number}) was detected and investigated on the PromaSecure NDR platform. ` +
            `Source IP <strong>${r.src_ip || 'unknown'}</strong> was observed targeting <strong>${r.dst_ip || 'unknown'}</strong> ` +
            `across <strong>${sessions.length}</strong> captured network sessions totalling <strong>${fmtBytes(totalBytes)}</strong> ` +
            `and <strong>${totalPackets.toLocaleString()}</strong> packets. ` +
            (events.length ? `${events.length} correlated NDR event${events.length > 1 ? 's were' : ' was'} generated. ` : '') +
            `The incident was resolved by analyst <strong>${r.analyst}</strong> and closed on <strong>${r.closed_at}</strong>.`;

        // ── Analyst declaration ────────────────────────────────────────
        const decl = `I, <strong>${r.analyst}</strong>, hereby certify that I personally conducted a thorough forensic analysis of ` +
            `incident <strong>${r.case_number}</strong> involving detected <strong>${tag1}</strong> activity. ` +
            `The investigation included review of <strong>${sessions.length}</strong> PCAP network capture sessions, ` +
            `<strong>${totalPackets.toLocaleString()}</strong> network packets, and <strong>${events.length}</strong> correlated NDR events. ` +
            `The attacker IP <strong>${r.src_ip || 'N/A'}</strong> was identified as the origin of malicious activity targeting ` +
            `victim endpoint <strong>${r.dst_ip || 'N/A'}</strong>. ` +
            `All findings and conclusions documented in this report are accurate to the best of my professional knowledge. ` +
            `The resolution actions taken are consistent with organizational security policy and incident response procedures.`;

        // ── Severity colors ────────────────────────────────────────────
        const sevMap: Record<string,{bg:string;col:string;bdr:string}> = {
            CRITICAL: {bg:'#fef2f2', col:'#dc2626', bdr:'#fecaca'},
            HIGH:     {bg:'#fff7ed', col:'#c2410c', bdr:'#fed7aa'},
            MEDIUM:   {bg:'#fefce8', col:'#a16207', bdr:'#fde68a'},
            LOW:      {bg:'#f0fdf4', col:'#15803d', bdr:'#bbf7d0'},
        };
        const sv = sevMap[(r.severity || '').toUpperCase()] || {bg:'#f8fafc',col:'#475569',bdr:'#cbd5e1'};

        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Incident Report — ${r.case_number}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
@page{size:A4 portrait;margin:0}
html,body{width:21cm;background:#fff;color:#1a2030;font-family:'Segoe UI',Arial,sans-serif;font-size:11.5px}
body{padding:1.8cm 2cm 1.5cm;min-height:29.7cm}
*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}

/* ── Page Header ── */
.ph{display:flex;justify-content:space-between;align-items:flex-start;
  border-bottom:3px solid #1e3a5f;padding-bottom:14px;margin-bottom:22px}
.brand-name{font-size:20px;font-weight:900;letter-spacing:.05em;color:#1e3a5f}
.brand-sub{font-size:8.5px;letter-spacing:.2em;text-transform:uppercase;color:#64748b;margin-top:2px}
.ph-meta{text-align:right;font-size:9px;color:#64748b;line-height:1.8}
.ph-meta .cnum{font-size:13px;font-weight:800;color:#0f172a;display:block}
.confidential{display:inline-block;padding:2px 10px;border-radius:3px;
  background:#fef2f2;border:1px solid #fecaca;color:#dc2626;
  font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px}

/* ── Title block ── */
h1{font-size:15px;font-weight:800;color:#0f172a;line-height:1.35;margin-bottom:6px}
.badges{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:18px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:9px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}

/* ── Sections ── */
h2{font-size:9px;text-transform:uppercase;letter-spacing:.16em;color:#64748b;
   border-bottom:1px solid #e2e8f0;padding-bottom:5px;margin:20px 0 10px;font-weight:700}
.exec-box{border-left:4px solid #1e3a5f;background:#f8fafc;padding:11px 14px;
  border-radius:0 6px 6px 0;font-size:11px;line-height:1.75;color:#334155;margin-bottom:0}
.exec-box strong{color:#0f172a}

/* ── Meta grid ── */
.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px 18px;
  background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px}
.mi label{display:block;font-size:8px;text-transform:uppercase;letter-spacing:.14em;color:#94a3b8;margin-bottom:3px}
.mi span{font-size:11px;color:#0f172a;font-weight:600;font-family:'Courier New',monospace}
.red{color:#dc2626!important}.blue{color:#1d4ed8!important}

/* ── Stats row ── */
.stats-row{display:flex;gap:10px;margin-top:0}
.stat{flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
  padding:10px;text-align:center}
.stat-v{font-size:18px;font-weight:800;color:#1e3a5f}
.stat-l{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#94a3b8;margin-top:2px}

/* ── Chart containers ── */
.chart-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;margin-bottom:0}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}

/* ── Tables ── */
.tbl-wrap{overflow:hidden;border-radius:6px;border:1px solid #e2e8f0}
table{width:100%;border-collapse:collapse;font-size:9.5px}
thead{display:table-header-group}
th{padding:6px 9px;background:#1e3a5f;color:#fff;text-align:left;
   font-size:8.5px;text-transform:uppercase;letter-spacing:.1em;font-weight:700}
td{padding:5px 9px;border-bottom:1px solid #f1f5f9;color:#334155;font-family:'Courier New',monospace;font-size:9.5px}
tr{page-break-inside:avoid;break-inside:avoid}
tr:last-child td{border-bottom:none}
tr:nth-child(even) td{background:#fafbfc}

/* ── Print page-break controls ── */
h2{page-break-after:avoid;break-after:avoid}
.stats-row{page-break-inside:avoid;break-inside:avoid}
.chart-row{page-break-inside:avoid;break-inside:avoid}
.chart-box{page-break-inside:avoid;break-inside:avoid}
.meta-grid{page-break-inside:avoid;break-inside:avoid}
.sig-row{page-break-inside:avoid;break-inside:avoid}
.decl-box{page-break-inside:avoid;break-inside:avoid}
.exec-box{page-break-inside:avoid;break-inside:avoid}
.res-box{page-break-inside:avoid;break-inside:avoid}
.tbl-wrap{page-break-before:auto}
.chart-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:#64748b;margin-bottom:8px;page-break-after:avoid;break-after:avoid}

/* ── Resolution/Notes ── */
.res-box{background:#f0fdf4;border-left:4px solid #059669;border-radius:0 6px 6px 0;
  padding:11px 14px;font-size:11px;line-height:1.75;color:#14532d;white-space:pre-wrap}
.intel-ok{display:flex;align-items:center;gap:8px;background:#f0fdf4;
  border:1px solid #bbf7d0;border-radius:6px;padding:8px 12px;
  font-size:10.5px;color:#15803d;font-weight:600;margin-top:10px}

/* ── Declaration ── */
.decl-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
  padding:14px;font-size:11px;line-height:1.8;color:#475569}
.decl-box strong{color:#0f172a}
.sig-row{display:flex;gap:28px;margin-top:28px}
.sig-blk{flex:1}
.sig-line{border-bottom:1.5px solid #1e3a5f;height:34px;margin-bottom:5px}
.sig-lbl{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#94a3b8}

/* ── Page footer (fixed on print) ── */
.pg-footer{position:fixed;bottom:0;left:0;right:0;padding:6px 2cm;
  border-top:1px solid #e2e8f0;background:#fff;
  display:flex;justify-content:space-between;font-size:8px;color:#94a3b8}
</style>
</head>
<body>

<!-- Page Header -->
<div class="ph">
  <div>
    <div class="brand-name">PROMASECURE NDR</div>
    <div class="brand-sub">Security Operations — Incident Response</div>
  </div>
  <div class="ph-meta">
    <span class="cnum">${r.case_number}</span>
    Generated: ${r.closed_at}<br/>
    Analyst: <strong>${r.analyst}</strong><br/>
    Classification: <strong>CONFIDENTIAL</strong>
  </div>
</div>

<!-- Classification + Badges -->
<div class="confidential">&#9888; Confidential — Internal Use Only</div>
<h1>${r.title || r.case_number}</h1>
<div class="badges">
  <span class="badge" style="background:${sv.bg};color:${sv.col};border:1px solid ${sv.bdr}">${r.severity || '—'}</span>
  <span class="badge" style="background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe">${r.priority || '—'}</span>
  <span class="badge" style="background:#f0fdf4;color:#15803d;border:1px solid #bbf7d0">${r.status}</span>
  ${r.tags ? r.tags.split(',').map((t: string) => `<span class="badge" style="background:#f1f5f9;color:#475569;border:1px solid #e2e8f0">${t.trim()}</span>`).join('') : ''}
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<div class="exec-box">${execSum}</div>

<!-- Incident Details -->
<h2 style="margin-top:20px">Incident Details</h2>
<div class="meta-grid">
  <div class="mi"><label>Case Number</label><span>${r.case_number}</span></div>
  <div class="mi"><label>Lead Analyst</label><span>${r.analyst}</span></div>
  <div class="mi"><label>Closed / Resolved</label><span style="font-family:'Segoe UI',Arial;font-size:10.5px">${r.closed_at}</span></div>
  <div class="mi"><label>Attacker IP</label><span class="red">${r.src_ip || '—'}</span></div>
  <div class="mi"><label>Victim IP</label><span class="blue">${r.dst_ip || '—'}</span></div>
  <div class="mi"><label>Severity / Priority</label><span>${r.severity} / ${r.priority || '—'}</span></div>
  <div class="mi" style="grid-column:1/-1"><label>Attack Tags</label><span style="font-family:'Segoe UI',Arial;color:#475569;font-weight:400">${r.tags || '—'}</span></div>
  ${r.description ? `<div class="mi" style="grid-column:1/-1"><label>Description</label><span style="font-family:'Segoe UI',Arial;color:#334155;font-weight:400;white-space:pre-wrap;font-size:10.5px">${r.description}</span></div>` : ''}
</div>

<!-- Traffic Statistics -->
<h2 style="margin-top:20px">Network Traffic Summary</h2>
<div class="stats-row">
  <div class="stat"><div class="stat-v">${sessions.length}</div><div class="stat-l">PCAP Sessions</div></div>
  <div class="stat"><div class="stat-v">${fmtBytes(totalBytes)}</div><div class="stat-l">Total Traffic</div></div>
  <div class="stat"><div class="stat-v">${totalPackets.toLocaleString()}</div><div class="stat-l">Total Packets</div></div>
  <div class="stat"><div class="stat-v">${srcIps.size}</div><div class="stat-l">Source IPs</div></div>
  <div class="stat"><div class="stat-v">${dstIps.size}</div><div class="stat-l">Dest IPs</div></div>
  <div class="stat"><div class="stat-v">${events.length}</div><div class="stat-l">NDR Events</div></div>
</div>

<!-- Charts: 4-panel analysis -->
${protoEntries.length ? `
<h2 style="margin-top:20px">PCAP Traffic Analysis</h2>

${timelineHtml}

<div class="chart-row" style="margin-top:14px">
  <div>
    <div class="chart-lbl">Protocol Distribution (Sessions)</div>
    <div class="chart-box">
      <svg width="100%" viewBox="0 0 380 ${c1H}" xmlns="http://www.w3.org/2000/svg">${c1Bars}</svg>
    </div>
  </div>
  <div>
    <div class="chart-lbl">Protocol Distribution (Bytes)</div>
    <div class="chart-box">
      <svg width="100%" viewBox="0 0 380 ${c2H}" xmlns="http://www.w3.org/2000/svg">${c2Bars}</svg>
    </div>
  </div>
</div>

${topSess.length ? `
<div style="margin-top:14px">
  <div class="chart-lbl">Top Connections by Traffic Volume</div>
  <div class="chart-box">
    <svg width="100%" viewBox="0 0 460 ${c3H}" xmlns="http://www.w3.org/2000/svg">${c3Bars}</svg>
  </div>
</div>` : ''}` : ''}

<!-- PCAP Sessions Table -->
${sessions.length ? `
<h2 style="margin-top:20px">PCAP Session Log (${sessions.length} sessions)</h2>
<div class="tbl-wrap">
<table>
  <thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Packets</th></tr></thead>
  <tbody>${sessRows}</tbody>
</table>
</div>` : ''}

<!-- NDR Events -->
${events.length ? `
<h2 style="margin-top:20px">Correlated NDR Events (${events.length})</h2>
<div class="tbl-wrap">
<table>
  <thead><tr><th>Timestamp</th><th>Event Type</th><th>Source</th><th>Destination</th><th>Details</th></tr></thead>
  <tbody>${eventRows}</tbody>
</table>
</div>` : ''}

<!-- Resolution -->
<h2 style="margin-top:20px">Resolution</h2>
<div class="res-box">${r.resolution}</div>
${r.intel_added ? `<div class="intel-ok"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#15803d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,8 6,12 14,4"/></svg>${r.intel_added}</div>` : ''}

<!-- Analyst Declaration -->
<h2 style="margin-top:24px">Analyst Declaration &amp; Sign-Off</h2>
<div class="decl-box">${decl}</div>
<div class="sig-row">
  <div class="sig-blk"><div class="sig-line"></div><div class="sig-lbl">Analyst Signature: ${r.analyst}</div></div>
  <div class="sig-blk"><div class="sig-line"></div><div class="sig-lbl">Date: ${r.closed_at}</div></div>
  <div class="sig-blk"><div class="sig-line"></div><div class="sig-lbl">Case Ref: ${r.case_number}</div></div>
</div>

<!-- Page Footer -->
<div class="pg-footer">
  <span>PromaSecure NDR Platform &nbsp;·&nbsp; ${r.case_number}</span>
  <span>CONFIDENTIAL — Internal Use Only</span>
  <span>${r.closed_at}</span>
</div>

</body></html>`;
    }

    _doUpdateStatus(status: string) {
        const c = this.selectedCase();
        if (!c) return;
        this.api.updateSoarCaseStatus(c.id, status).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    const now = Math.floor(Date.now() / 1000);
                    this.selectedCase.update(sc => sc ? {
                        ...sc,
                        status,
                        closed_at: ['Resolved', 'Closed', 'False Positive'].includes(status) ? now : null,
                    } : sc);
                    this.loadCases();
                }
            },
            error: (err) => alert('Status update failed: ' + (err.error?.message || err.message)),
        });
    }

    addComment() {
        const c = this.selectedCase();
        if (!this.newComment.trim() || !c) return;
        this.api.addSoarCaseComment(c.id, this.newComment).subscribe((res: any) => {
            if (res.status === 'success') { this.newComment = ''; this.openCase(c); }
        });
    }

    collectPcap() {
        const c = this.selectedCase();
        const cid = c?.community_id;
        if (!cid || this.collectingPcap()) return;
        this.collectingPcap.set(true);
        this.collectPcapDone.set(false);
        this.api.triggerEvidenceCapture(cid).subscribe({
            next: () => { this.collectingPcap.set(false); this.collectPcapDone.set(true); setTimeout(() => this.openCase(c), 4000); },
            error: () => { this.collectingPcap.set(false); this.collectPcapDone.set(true); },
        });
    }

    // ── Playbooks ─────────────────────────────────────────────────────────────
    togglePlaybook(pb: any) {
        pb.enabled = pb.enabled === 1 ? 0 : 1;
        this.api.updateNativePlaybook(pb.id, {
            name: pb.name, description: pb.description, enabled: pb.enabled === 1,
            cond_field: pb.cond_field, cond_op: pb.cond_op, cond_value: pb.cond_value,
            action_type: pb.action_type, action_config: pb.action_config,
        }).subscribe(() => this.loadPlaybooks());
    }

    deletePlaybook(pb: any) {
        if (confirm(`Delete playbook ${pb.name}?`)) {
            this.api.deleteNativePlaybook(pb.id).subscribe(() => this.loadPlaybooks());
        }
    }

    savePlaybook() {
        if (!this.pbName) { this.pbError.set('Name is required'); return; }
        this.savingPb.set(true);
        this.pbError.set('');
        const data = {
            name: this.pbName, description: this.pbDesc, enabled: true,
            cond_field: this.pbCondField, cond_op: this.pbCondOp, cond_value: this.pbCondValue,
            action_type: this.pbActionType, action_config: JSON.stringify(this.pbActionConfig),
        };
        const request$ = this.editingPbId
            ? this.api.updateNativePlaybook(this.editingPbId, data)
            : this.api.createNativePlaybook(data);
        request$.subscribe({
            next: (res: any) => {
                this.savingPb.set(false);
                if (res.status === 'success') { this.showNewPlaybook.set(false); this.editingPbId = null; this.loadPlaybooks(); }
                else this.pbError.set(res.message);
            },
            error: () => { this.savingPb.set(false); this.pbError.set(this.editingPbId ? 'Failed to update playbook' : 'Failed to create playbook'); },
        });
    }

    initPlaybookModal() {
        this.editingPbId = null;
        this.pbName = '';
        this.pbDesc = '';
        this.pbCondField = 'score';
        this.pbCondOp = '>';
        this.pbCondValue = '75';
        this.pbActionType = 'slack';
        this.pbActionConfig = {};
        this.pbError.set('');
        this.showNewPlaybook.set(true);
    }

    openEditPlaybook(pb: any) {
        this.editingPbId = pb.id;
        this.pbName = pb.name;
        this.pbDesc = pb.description;
        this.pbCondField = pb.cond_field;
        this.pbCondOp = pb.cond_op;
        this.pbCondValue = pb.cond_value;
        this.pbActionType = pb.action_type;
        try { this.pbActionConfig = typeof pb.action_config === 'string' ? JSON.parse(pb.action_config) : (pb.action_config || {}); }
        catch { this.pbActionConfig = {}; }
        this.pbError.set('');
        this.showNewPlaybook.set(true);
    }

    // ── Condition helpers ─────────────────────────────────────────────────────
    get condOps(): { value: string; label: string }[] {
        switch (this.pbCondField) {
            case 'score':        return [{ value: '>',  label: '>' }, { value: '>=', label: '>=' }, { value: '<',  label: '<' }, { value: '<=', label: '<=' }, { value: '==', label: '==' }];
            case 'severity':
            case 'src_country':
            case 'sigma_tag':    return [{ value: '==', label: '==' }, { value: 'contains', label: 'contains' }];
            case 'threat_intel':
            default:             return [{ value: '==', label: '==' }];
        }
    }

    get condValueType(): 'text' | 'severity' | 'bool' {
        if (this.pbCondField === 'severity')     return 'severity';
        if (this.pbCondField === 'threat_intel') return 'bool';
        return 'text';
    }

    onCondFieldChange() {
        this.pbCondOp = this.condOps[0].value;
        if (this.pbCondField === 'threat_intel') this.pbCondValue = 'true';
        else if (this.pbCondField === 'severity') this.pbCondValue = 'HIGH';
        else this.pbCondValue = '75';
    }

    // ── Integrations ──────────────────────────────────────────────────────────
    integrationsByGroup(group: string): any[] {
        return this.integrationTypes.filter((t: any) => t.group === group);
    }

    getIntAbbr(type: string): string {
        return (this.integrationTypes as any[]).find((t: any) => t.type === type)?.abbr || type.slice(0,3).toUpperCase();
    }

    getIntIcon(type: string): string { return this.getIntAbbr(type); }

    get selectedIntType() {
        return this.integrationTypes.find(t => t.type === this.intType);
    }

    testIntegration() {
        this.testingInt.set(true);
        this.testResult.set('');
        this.api.testIntegration({ type: this.intType, config: this.intConfig }).subscribe({
            next: (data: any) => { this.testingInt.set(false); this.testResult.set(data.message); },
            error: () => { this.testingInt.set(false); this.testResult.set('❌ Connection failed'); },
        });
    }

    openEditIntegration(int: any) {
        this.editingIntId = int.id;
        this.intType = int.type;
        this.intName = int.name;
        this.intConfig = typeof int.config === 'object' ? { ...int.config } : {};
        this.testResult.set('');
        this.showNewIntegration.set(true);
    }

    saveIntegration() {
        this.savingInt.set(true);
        const payload = { name: this.intName || this.selectedIntType?.name, type: this.intType, config: this.intConfig };
        const request$ = this.editingIntId
            ? this.api.updateIntegration(this.editingIntId, payload)
            : this.api.saveIntegration(payload);
        request$.subscribe({
            next: () => { this.savingInt.set(false); this.showNewIntegration.set(false); this.editingIntId = null; this.intConfig = {}; this.intName = ''; this.loadIntegrations(); },
            error: () => this.savingInt.set(false),
        });
    }

    toggleIntegration(int: any) {
        int.enabled = !int.enabled;
        this.api.toggleIntegration({ id: int.id, enabled: int.enabled }).subscribe();
    }

    deleteIntegration(int: any) {
        if (!confirm(`Delete ${int.name}?`)) return;
        this.api.deleteIntegration({ id: int.id }).subscribe(() => this.loadIntegrations());
    }

    // ── Date / time formatting ─────────────────────────────────────────────────
    formatTs(ts: number): string {
        if (!ts) return '-';
        return new Date(ts * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    formatPcapTime(ms: number): string {
        if (!ms) return '-';
        return new Date(ms).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    formatDateShort(ts: any): string {
        if (!ts) return '-';
        const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    formatDate(ts: any) {
        if (!ts) return 'N/A';
        const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
        return d.toLocaleString();
    }
}
