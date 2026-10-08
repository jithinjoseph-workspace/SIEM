import { Component, Input, Output, EventEmitter, OnChanges, SimpleChanges, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';

declare var ForceGraph3D: any;
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { ArkimeService } from '../../services/arkime/arkime';
import {
  LucideAngularModule,
  Network,
  Package,
  X,
  Laptop,
  Monitor,
  Smartphone,
  Tablet,
  Cpu,
  Printer,
  Tv,
  HelpCircle,
  Globe,
  Server,
  Router,
  TriangleAlert,
  Users,
  Download,
  ExternalLink,
  Edit2,
  Check,
  Target,
  LayoutGrid,
  Waypoints,
  Bell,
  ChevronRight,
  Shield,
  ArrowUpRight,
  BarChart2,
  ChevronDown
} from 'lucide-angular';

@Component({
  selector: 'app-device-drawer',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './device-drawer.html',
  styleUrl: './device-drawer.css',
})
export class DeviceDrawer implements OnChanges {
  @Input() node: any = null;
  @Input() focusModeActive: boolean = false;
  @Output() closeDrawer = new EventEmitter<void>();
  @Output() focusRequested = new EventEmitter<string>();

  drawerTab: string = 'overview';
  
  selectedNodeConnections: any[] = [];
  loadingConnections = false;

  selectedNodeAlerts: any[] = [];
  loadingAlerts = false;

  pcapSessions: any[] = [];
  pcapLoading = false;
  pcapError = '';

  NetworkIcon = Network;
  PackageIcon = Package;
  XIcon = X;
  DownloadIcon = Download;
  ExternalLinkIcon = ExternalLink;
  EditIcon = Edit2;
  CheckIcon = Check;
  TargetIcon = Target;
  LayoutGridIcon = LayoutGrid;
  WaypointsIcon = Waypoints;
  BellIcon = Bell;
  ChevronRightIcon = ChevronRight;
  ShieldIcon = Shield;
  ArrowUpRightIcon = ArrowUpRight;
  BarChart2Icon = BarChart2;
  ChevronDownIcon = ChevronDown;
  UsersIcon = Users;

  isEditingName = false;
  editNameValue = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef, private arkime: ArkimeService) {}

  @ViewChild('topologyContainer') topologyContainer?: ElementRef;
  topologyGraph: any;

  ngOnChanges(changes: SimpleChanges) {
    if (changes['node'] && this.node) {
      this.setDrawerTab(this.drawerTab);
      // Pre-load connections for overview charts
      if (this.drawerTab !== 'connections') {
        const ip = this.node.active_ip || this.node.id || this.node.ip;
        if (ip) this.loadNodeConnections(ip);
      }
    }
  }

  initTopology() {
    if (this.drawerTab !== 'topology' || !this.topologyContainer || !this.node) return;
    if (typeof ForceGraph3D === 'undefined') return;

    if (!this.topologyGraph) {
      this.topologyGraph = ForceGraph3D()(this.topologyContainer.nativeElement)
        .backgroundColor('#000000')
        .width(this.topologyContainer.nativeElement.clientWidth)
        .height(this.topologyContainer.nativeElement.clientHeight || 300)
        .nodeLabel('id')
        .nodeAutoColorBy('group');
    }

    // Fetch localized data
    const ip = this.node.active_ip || this.node.id || this.node.ip;
    if (ip) {
      this.api.getNetworkMapNode(ip).subscribe(data => {
        if (data && data.nodes) {
          this.topologyGraph.graphData(data);
        }
      });
    }
  }

  get activityBars(): number[] {
    const ip = this.node?.id || this.node?.ip || '';
    const seed = ip.split('').reduce((a: number, c: string) => ((a * 31) + c.charCodeAt(0)) & 0xFFFF, 7);
    // Always at least 40 visual base so bars are never flat
    const conns = this.node?.connections || 0;
    const base = Math.max(40, Math.min(95, (conns / 40) * 100 + 40));
    return Array.from({length: 14}, (_, i) => {
      const v = Math.abs(Math.sin((seed * 0.01 + i) * 1.37));
      return Math.max(14, Math.min(95, v * (base - 12) + 14));
    });
  }

  get riskScore(): number {
    if (!this.node) return 0;
    if (this.node.criticality != null) return Math.min(100, this.node.criticality);
    if (this.node.threat) return 88;
    const conns = this.node.connections || 0;
    if (!this.isInternalNode(this.node)) return Math.min(60, 18 + Math.floor(conns / 100));
    return Math.min(35, 4 + Math.floor(conns / 150));
  }

  get topPeers(): any[] {
    return [...this.selectedNodeConnections]
      .sort((a: any, b: any) => (b.connections || 0) - (a.connections || 0))
      .slice(0, 4);
  }

  get topProtocols(): string[] {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const c of this.selectedNodeConnections) {
      for (const p of (c.protocols || [])) {
        if (!seen.has(p)) { seen.add(p); result.push(p); }
      }
    }
    return result.slice(0, 6);
  }

  getPeerBarWidth(peer: any): number {
    const max = this.topPeers.reduce((m: number, p: any) => Math.max(m, p.connections || 0), 1);
    return Math.round(((peer.connections || 0) / max) * 100);
  }

  setDrawerTab(tab: string) {
    this.drawerTab = tab;
    if (!this.node) return;

    if (tab === 'connections') {
      this.loadNodeConnections(this.node.active_ip || this.node.id || this.node.ip);
    } else if (tab === 'alerts') {
      this.loadNodeAlerts(this.node.active_ip || this.node.id || this.node.ip);
    } else if (tab === 'pcaps') {
      this.loadPcapSessions(this.node.active_ip || this.node.id || this.node.ip);
    } else if (tab === 'topology') {
      setTimeout(() => this.initTopology(), 100);
    }
  }

  loadNodeConnections(ip: string) {
    this.loadingConnections = true;
    this.selectedNodeConnections = [];
    this.api.getNetworkMapNode(ip).subscribe({
      next: (data: any) => {
        const edges = data.edges || [];
        this.selectedNodeConnections = edges.map((e: any) => ({
           peer: e.source === ip ? e.target : e.source,
           connections: e.connections,
           protocols: e.protocols || []
        }));
        this.loadingConnections = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingConnections = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadNodeAlerts(ip: string) {
    this.loadingAlerts = true;
    this.selectedNodeAlerts = [];
    this.api.getAlerts().subscribe({
      next: (hits: any[]) => {
        this.selectedNodeAlerts = hits.filter((h: any) => h.src_ip === ip || h.dst_ip === ip);
        this.loadingAlerts = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingAlerts = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadPcapSessions(ip: string) {
    this.pcapLoading = true;
    this.pcapSessions = [];
    this.pcapError = '';
    
    this.arkime.getSessions({ ip, limit: 10 }).subscribe({
      next: (res: any) => {
        this.pcapSessions = res.sessions || res.data || [];
        this.pcapLoading = false;
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.pcapError = 'Failed to load PCAP sessions';
        this.pcapLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  downloadPcap(sessionId: string) {
    this.arkime.downloadPcap(sessionId);
  }

  toggleFocus() {
    if (!this.node) return;
    this.focusRequested.emit(this.node.id || this.node.ip);
  }

  onClose() {
    this.closeDrawer.emit();
  }

  startEditName() {
    this.isEditingName = true;
    this.editNameValue = this.node.custom_name || this.node.hostname || this.node.label || '';
  }

  saveName() {
    // Uses the IP explicitly to ensure backend API route matches
    const ip = this.node.active_ip || this.node.ip || this.node.id;
    if (!ip) return;

    this.api.updateAsset(ip, { custom_name: this.editNameValue }).subscribe({
      next: () => {
        this.node.custom_name = this.editNameValue;
        this.node.label = this.editNameValue;
        this.isEditingName = false;
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        console.error('Failed to update asset name:', err);
        this.isEditingName = false;
        this.cdr.detectChanges();
      }
    });
  }

  cancelEditName() {
    this.isEditingName = false;
  }

  copyToClipboard(text: string) {
    if (!text) return;
    navigator.clipboard.writeText(text).catch(() => {});
  }

  onFaviconError(event: Event) {
    const img = event.target as HTMLImageElement;
    img.style.display = 'none';
    const icon = img.closest('.website-card__icon');
    if (icon) (icon as HTMLElement).setAttribute('data-fallback', '🌐');
  }

  isInternalNode(node: any): boolean {
    const ip = node?.active_ip || node?.ip || node?.id || '';
    // RFC-1918 ranges are always internal regardless of what the API says
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.')) return true;
    if (ip.startsWith('172.')) {
      const second = parseInt(ip.split('.')[1] ?? '0', 10);
      if (second >= 16 && second <= 31) return true;
    }
    // For non-private IPs fall back to the API field
    return node?.is_internal ?? false;
  }

  getDrawerIcon(node: any): any {
    const type = node?.type || node?.device_type;
    if (type === 'cluster') return Users;
    if (type === 'laptop') return Laptop;
    if (type === 'desktop') return Monitor;
    if (type === 'phone' || type === 'mobile') return Smartphone;
    if (type === 'tablet') return Tablet;
    if (type === 'iot') return Cpu;
    if (type === 'printer') return Printer;
    if (type === 'tv' || type === 'media') return Tv;
    if (type === 'server') return Server;
    if (type === 'router' || type === 'gateway' || type === 'firewall' || type === 'switch') return Router;
    
    const isInternal = this.isInternalNode(node);
    if (isInternal) return Router;
    if (node?.threat) return TriangleAlert;
    return isInternal ? HelpCircle : Globe;
  }

  getNodeTypeClass(node: any): string {
    if (node?.threat) return 'threat';
    return this.isInternalNode(node) ? 'internal' : 'external';
  }

  sanitizeRuleName(name: any): string {
    return String(name || '')
      .replace(/\bSURICATA\b/gi, 'Agent-S')
      .replace(/\bZEEK\b/gi, 'Agent-Z');
  }
}
