import { Component, OnInit, OnDestroy, ElementRef, ViewChild, ChangeDetectorRef, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../../services/api/api';
import { ArkimeService } from '../../../services/arkime/arkime';
import { NetworkDataService } from './services/network-data.service';
import { NetworkPhysicsService } from './services/network-physics.service';
import * as d3 from 'd3';
import {
  CircleDot,
  Download,
  ExternalLink,
  GitBranch,
  Globe,
  LucideAngularModule,
  Network,
  Package,
  RefreshCw,
  Router,
  Server,
  TriangleAlert,
  X,
  Laptop,
  Monitor,
  Smartphone,
  Tablet,
  Cpu,
  Printer,
  Tv,
  HelpCircle,
  Users,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ChevronLeft
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';


const DEVICE_PATHS: Record<string, string> = {
  laptop: 'M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16',
  mobile: 'M5 4a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4zm7 14h.01',
  phone: 'M5 4a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4zm7 14h.01',
  router: 'M4 14v7m16-7v7m-8-7v7M2 10h20a2 2 0 0 1 2 2v2H0v-2a2 2 0 0 1 2-2zM8 2v2m8-2v2',
  server: 'M4 4h16v8H4zm0 8h16v8H4zm4-4h.01M8 16h.01',
  printer: 'M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2m-4-6h.01M6 14h12v8H6z',
  tv: 'm16 3-4 4-4-4m13 6H3a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h18a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2Z',
  desktop: 'M2 5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V5zm6 12v4m8-4v4m-8 0h8',
  iot: 'M12 2v4m-4-3.5L9.5 5.5M16 2.5 14.5 5.5M6 8a6 6 0 1 0 12 0H6z',
  globe: 'M22 12A10 10 0 1 1 12 2a10 10 0 0 1 10 10z M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',
  cluster: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2 M9 7a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M23 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75',
  github: 'M15 22v-4a4.8 4.8 0 0 0-1-3.2c3 0 6-2 6-5.9 0-1.4-.5-2.5-1.3-3.4l.1-1.2s-.5-1.5-1.5-2.2L12 7l-2.3-1c-1 .7-1.5 2.2-1.5 2.2l.1 1.2A5 5 0 0 0 7 12.9c0 4 3 6 6 6-.5.4-1 .9-1.2 1.8-1 .4-2 .4-3-1s-1.5-1.6-1.5-1.6c-.9-.2-1.4.1-1.4.1l.1.3c.4.1.7.5 1 1s1.3 1.5 2.5 1.5c1.4.2 2.5-.2 2.5-.2v3.1',
  youtube: 'M2.5 17a24.1 24.1 0 0 1 0-10 2 2 0 0 1 1.4-1.4 49.5 49.5 0 0 1 16.2 0A2 2 0 0 1 21.5 7a24.1 24.1 0 0 1 0 10 2 2 0 0 1-1.4 1.4 49.5 49.5 0 0 1-16.2 0A2 2 0 0 1 2.5 17 M10 15l5-3-5-3z',
  cloud: 'M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z',
  apple: 'M12 20.94c1.5 0 2.75 1.06 4 1.06 3 0 6-8 6-12.22A4.91 4.91 0 0 0 17 5c-2.22 0-4 1.44-5 2-1-.56-2.78-2-5-2a4.9 4.9 0 0 0-5 4.78C2 14 5 22 8 22c1.25 0 2.5-1.06 4-1.06Z M10 2c1 .5 2 2 2 5'
};

import { DeviceDrawer } from '../../../components/device-drawer/device-drawer';

@Component({
  selector: 'app-network-map',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, DeviceDrawer],
  templateUrl: './network-map.html',
  styleUrl: './network-map.css',
})
export class NetworkMap implements OnInit, OnDestroy {
  @ViewChild('mapSvg', { static: true }) svgRef!: ElementRef;
  zoomBehavior: any;

  nodeCount: number = 0;
  edgeCount: number = 0;
  viewState: 'loading' | 'loaded' | 'error' | 'empty' = 'loading';
  errorMessage: string = '';
  @Input() previewMode = false;
  selectedNode: any = null;
  lastUpdated: string = '--';

  showInsights: boolean = false;

  nodesData: any[] = [];
  edgesData: any[] = [];

  searchQuery: string = '';
  searchDebounce: any;
  isSearchActive: boolean = false;
  searchMatches: Set<string> = new Set();

  CircleDotIcon = CircleDot;
  DownloadIcon = Download;
  ExternalLinkIcon = ExternalLink;
  GitBranchIcon = GitBranch;
  GlobeIcon = Globe;
  NetworkIcon = Network;
  PackageIcon = Package;
  RefreshIcon = RefreshCw;
  RouterIcon = Router;
  ServerIcon = Server;
  ThreatIcon = TriangleAlert;
  XIcon = X;
  ArrowLeftIcon = ArrowLeft;
  ChevronDownIcon = ChevronDown;
  ChevronRightIcon = ChevronRight;
  ChevronLeftIcon = ChevronLeft;

  isDsbCollapsed: boolean = false;

  toggleDsb() {
    this.isDsbCollapsed = !this.isDsbCollapsed;
    setTimeout(() => window.dispatchEvent(new Event('resize')), 250);
  }

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(
    private api: Api,
    private cdr: ChangeDetectorRef,
    private arkime: ArkimeService,
    private dataService: NetworkDataService,
    private physics: NetworkPhysicsService,
    private auth: AuthService
  ) {}

  ngOnDestroy() {
    this.physics.destroy();
    clearTimeout(this.searchDebounce);
  }

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.loadMap();
  }

  getDrawerIcon(node: any): any {
    if (node?.type === 'cluster') return Users;
    if (node?.type === 'laptop') return Laptop;
    if (node?.type === 'desktop') return Monitor;
    if (node?.type === 'phone' || node?.type === 'mobile') return Smartphone;
    if (node?.type === 'tablet') return Tablet;
    if (node?.type === 'iot') return Cpu;
    if (node?.type === 'printer') return Printer;
    if (node?.type === 'tv' || node?.type === 'media') return Tv;
    if (node?.type === 'server') return Server;
    if (node?.type === 'router' || node?.type === 'gateway' || node?.type === 'firewall' || node?.type === 'switch') return Router;
    if (node?.is_internal) return Router;
    if (node?.threat) return TriangleAlert;
    return node?.is_internal ? HelpCircle : Globe;
  }

  getNodeIconPath(node: any): string {
    if (node?.type === 'cluster') return DEVICE_PATHS['cluster'];
    if (node?.threat) return DEVICE_PATHS['unknown'];
    
    // Handle synonyms
    const type = node?.type || '';
    if ((type === 'phone' || type === 'mobile') && DEVICE_PATHS['phone']) return DEVICE_PATHS['phone'];
    if ((type === 'tv' || type === 'media') && DEVICE_PATHS['tv']) return DEVICE_PATHS['tv'];
    if ((type === 'router' || type === 'gateway' || type === 'firewall' || type === 'switch') && DEVICE_PATHS['router']) return DEVICE_PATHS['router'];

    if (node?.type && DEVICE_PATHS[node.type]) return DEVICE_PATHS[node.type];
    if (node.is_internal) return DEVICE_PATHS['router'];
    
    // We now use full-color favicons for most brands, but keep these as fallbacks
    const label = (node.label || node.id || '').toLowerCase();
    if (label.includes('github')) return DEVICE_PATHS['github'];
    if (label.includes('youtube') || label.includes('googlevideo')) return DEVICE_PATHS['youtube'];
    if (label.includes('apple') || label.includes('icloud') || label.includes('mzstatic')) return DEVICE_PATHS['apple'];
    if (label.includes('aws') || label.includes('amazonaws') || label.includes('cloudfront')) return DEVICE_PATHS['cloud'];
    if (label.includes('google')) return DEVICE_PATHS['cloud'];
    
    return DEVICE_PATHS['globe'];
  }

  hasFavicon(node: any): boolean {
    const d = this.getDomain(node);
    if (!d) return false;
    // Skip mDNS service names, reverse DNS zones, and bare TLDs
    if (d.startsWith('_')) return false;
    if (d.endsWith('.arpa') || d.endsWith('.local')) return false;
    if (d.includes('._tcp') || d.includes('._udp') || d.includes('._sub')) return false;
    // Must look like a real domain (contains at least one dot and no spaces)
    if (!d.includes('.') || d.includes(' ')) return false;
    return node.type === 'domain' || (!node.is_internal && node.type !== 'cluster' && node.label && node.label !== node.id);
  }

  getDomain(node: any): string {
    if (!node || !node.label) return '';
    const raw = String(node.label).split(' ')[0];
    // Reject obvious unsafe values: contains path or port separators
    if (raw.includes('/') || raw.includes(':')) return '';
    // Reject plain IPv4 addresses
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) return '';
    // Strict hostname regex: labels 1-63 chars, overall <=253, TLD alpha-only 2-63
    const hostnameRegex = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$/;
    if (!hostnameRegex.test(raw)) return '';
    // Defensive: no consecutive dots
    if (raw.includes('..')) return '';
    return raw.toLowerCase();
  }

  getNodeKindLabel(node: any): string {
    if (node?.threat) return 'Threat Indicator';
    if (node?.type === 'domain') return 'External Domain';
    if (node?.type && node.type !== 'unknown' && node.type !== 'external') {
      return node.type.charAt(0).toUpperCase() + node.type.slice(1);
    }
    return node?.is_internal ? 'Internal Host' : 'External Server';
  }

  getNodeTypeClass(node: any): string {
    if (node?.threat) return 'threat';
    return node?.is_internal ? 'internal' : 'external';
  }

  clearSelection() {
    this.selectedNode = null;
    this.focusMode = false;
    d3.select(this.svgRef.nativeElement).selectAll('.topology-node').classed('is-selected', false);
    this.applyFocus();
  }

  toggleInsights() {
    this.showInsights = !this.showInsights;
  }

  focusMode: boolean = false;
  activeFilter: string = 'all';
  selectedPathNode: any = null;

  get internalNodes(): any[] {
    return [...this.nodesData]
      .filter((n: any) => n.is_internal && n.type !== 'cluster')
      .sort((a: any, b: any) => {
        const aGw = ['router','gateway','firewall','switch'].includes(a.type);
        const bGw = ['router','gateway','firewall','switch'].includes(b.type);
        if (aGw && !bGw) return -1;
        if (!aGw && bGw) return 1;
        return (b.connections || 0) - (a.connections || 0);
      });
  }

  get gatewayNode(): any {
    const explicit = this.nodesData.find((n: any) =>
      n.is_internal && ['router','gateway','firewall'].includes(n.type)
    );
    if (explicit) return explicit;
    return [...this.nodesData]
      .filter((n: any) => n.is_internal)
      .sort((a: any, b: any) => (b.connections || 0) - (a.connections || 0))[0];
  }

  get selectedPathExternals(): any[] {
    if (!this.selectedPathNode) return [];
    const nodeId = this.selectedPathNode.id;
    const connectedIds = new Set<string>();
    for (const e of this.edgesData) {
      const src = (e.source as any)?.id ?? (e.source as string);
      const tgt = (e.target as any)?.id ?? (e.target as string);
      if (src === nodeId) connectedIds.add(tgt);
      if (tgt === nodeId) connectedIds.add(src);
    }
    return this.nodesData
      .filter((n: any) => connectedIds.has(n.id) && !n.is_internal)
      .sort((a: any, b: any) => (b.connections || 0) - (a.connections || 0))
      .slice(0, 10);
  }

  selectPathNode(node: any) {
    this.selectedPathNode = node;
    this.selectedNode = node;
    this.focusMode = true;
    this.loadFocusMode(node.id);
    this.cdr.detectChanges();
  }

  isIPAddress(val: string): boolean {
    if (!val) return false;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(val) || val.includes(':');
  }

  exitDeviceFocus() {
    this.selectedPathNode = null;
    this.focusMode = false;
    this.loadMap(true);
  }

  get internalCount(): number { return this.nodesData.filter((n: any) => n.is_internal && !n.threat).length; }
  get externalCount(): number { return this.nodesData.filter((n: any) => !n.is_internal && !n.threat).length; }
  get threatCount():   number { return this.nodesData.filter((n: any) => n.threat).length; }
  get trafficCount():  number { return this.nodesData.filter((n: any) => (n.connections || 0) > 5).length; }

  get topTalkers(): any[] {
    return [...this.nodesData]
      .filter((n: any) => (n.connections || 0) > 0)
      .sort((a: any, b: any) => (b.connections || 0) - (a.connections || 0))
      .slice(0, 5);
  }

  get threatNodes(): any[] {
    return this.nodesData.filter((n: any) => n.threat);
  }

  setFilter(filter: string) {
    this.activeFilter = filter;
    const svg = d3.select(this.svgRef.nativeElement);

    svg.selectAll<SVGGElement, any>('g.topology-node').transition().duration(220).style('opacity', (d: any) => {
      if (filter === 'all') return 1;
      if (filter === 'internal') return (d.is_internal && !d.threat) ? 1 : 0.08;
      if (filter === 'external') return (!d.is_internal && !d.threat) ? 1 : 0.08;
      if (filter === 'threat') return d.threat ? 1 : 0.08;
      if (filter === 'traffic') return (d.connections || 0) > 5 ? 1 : 0.08;
      return 1;
    });

    svg.selectAll<SVGLineElement, any>('line').transition().duration(220).style('opacity', (d: any) => {
      if (filter === 'all') return 1;
      if (filter === 'internal') {
        const si = d.source?.is_internal && !d.source?.threat;
        const ti = d.target?.is_internal && !d.target?.threat;
        return (si || ti) ? 0.5 : 0.04;
      }
      if (filter === 'external') return (!d.source?.is_internal || !d.target?.is_internal) ? 0.5 : 0.04;
      if (filter === 'threat') return (d.source?.threat || d.target?.threat) ? 0.8 : 0.04;
      if (filter === 'traffic') return (d.connections || 0) > 5 ? 1 : 0.04;
      return 1;
    });
  }

  toggleFocus() {
    this.focusMode = !this.focusMode;
    if (this.focusMode && this.selectedNode) {
      this.loadFocusMode(this.selectedNode.id);
    } else {
      this.loadMap(true);
    }
  }

  applyFocus() {
    // Legacy local focus behavior can be skipped since we now fetch the sub-graph
  }

  onSearchChange(event: any) {
    this.searchQuery = event.target.value;
    clearTimeout(this.searchDebounce);
    
    if (!this.searchQuery.trim()) {
      this.isSearchActive = false;
      this.searchMatches.clear();
      this.renderGraph(this.nodesData, this.edgesData);
      return;
    }

    this.searchDebounce = setTimeout(() => {
      this.isSearchActive = true;
      this.searchMatches.clear();
      
      // 1. Client-side instant match (bulletproof for visible nodes)
      const q = this.searchQuery.trim().toLowerCase();
      this.nodesData.forEach(n => {
         const idMatch      = n.id        && n.id.toLowerCase().includes(q);
         const labelMatch   = n.label     && n.label.toLowerCase().includes(q);
         const activeIpMatch = n.active_ip && n.active_ip.toLowerCase().includes(q);
         const macMatch     = n.mac       && n.mac.toLowerCase().includes(q);

         // Hybrid Asset Model: also search through ip_history timestamps
         let historyMatch = false;
         if (n.ip_history && n.ip_history !== '[]') {
           try {
             const history: Array<{ip: string}> = JSON.parse(n.ip_history);
             historyMatch = history.some(entry => entry.ip && entry.ip.toLowerCase().includes(q));
           } catch { /* ignore malformed JSON */ }
         }

         // Passive DNS: search through domains
         const primaryDomainMatch = n.primary_domain && n.primary_domain.toLowerCase().includes(q);
         const allDomainsMatch    = n.all_domains && n.all_domains.some((d: string) => d.toLowerCase().includes(q));
         
         // Search inside clusters
         const membersMatch       = n.member_ips && n.member_ips.some((m: string) => m.toLowerCase().includes(q));

         if (idMatch || labelMatch || activeIpMatch || macMatch || historyMatch || primaryDomainMatch || allDomainsMatch || membersMatch) {
             this.searchMatches.add(n.id);
         }
      });
      
      // Paint immediately for instant UX feedback
      this.renderGraph(this.nodesData, this.edgesData);

      // 2. Server-side deep search (for clustered/unrendered nodes)
      this.api.searchNetworkMap(this.searchQuery).subscribe({
        next: (ids: string[]) => {
          let hasNewMatches = false;
          ids.forEach(id => {
              if (!this.searchMatches.has(id)) {
                  this.searchMatches.add(id);
                  hasNewMatches = true;
              }
              // Check if this ID is hidden inside a cluster on the current map
              this.nodesData.forEach((n: any) => {
                  if (n.type === 'cluster' && n.member_ips && n.member_ips.includes(id)) {
                      if (!this.searchMatches.has(n.id)) {
                          this.searchMatches.add(n.id);
                          hasNewMatches = true;
                      }
                  }
              });
          });

          // Apply backend search state if there are new out-of-bounds nodes
          if (hasNewMatches) {
             this.renderGraph(this.nodesData, this.edgesData);
          }

          if (ids.length > 0) {
            let matchedNode = this.nodesData.find((n: any) => n.id === ids[0]);
            let clusterToExpand = null;
            if (!matchedNode) {
              clusterToExpand = this.nodesData.find((n: any) => n.type === 'cluster' && n.member_ips?.includes(ids[0]));
            }

            if (clusterToExpand) {
              this.expandCluster(clusterToExpand);
              setTimeout(() => {
                 let expandedMatch = this.nodesData.find((n: any) => n.id === ids[0]);
                 if (expandedMatch) this.zoomToNode(expandedMatch);
              }, 400);
            } else if (matchedNode) {
              this.zoomToNode(matchedNode);
            }
          }
        },
        error: () => {},
      });
    }, 300);
  }

  zoomToNode(node: any, targetScale: number = 2) {
    if (node.x === undefined || node.y === undefined || !this.zoomBehavior) return;
    const svgEl = this.svgRef.nativeElement;
    const width = svgEl.clientWidth || 1000;
    const height = svgEl.clientHeight || 600;

    const transform = d3.zoomIdentity
      .translate(width / 2, height / 2)
      .scale(targetScale)
      .translate(-node.x, -node.y);

    d3.select(svgEl).transition().duration(800).call(this.zoomBehavior.transform, transform);
  }

  expandCluster(clusterNode: any) {
    if (!clusterNode.member_ips || clusterNode.member_ips.length === 0) return;

    // ── Step 1: Capture graph-space coordinates NOW, before anything changes.
    // clusterNode is a live D3 datum — it has the settled x/y from the simulation.
    // Once we call renderGraph / updateSimulation these may drift, so freeze them.
    const anchorX = clusterNode.x;
    const anchorY = clusterNode.y;

    this.viewState = 'loading';
    this.errorMessage = '';
    this.dataService.expandCluster(clusterNode, this.nodesData, this.edgesData).subscribe({
      next: (data) => {
        // ── Step 2: Preserve ALL existing node positions (no scatter).
        const oldNodesMap = new Map(this.nodesData.map((n: any) => [n.id, n]));
        this.nodesData = data.nodes.map((newNode: any) => {
          const oldNode = oldNodesMap.get(newNode.id);
          if (oldNode) {
            // Existing node — keep its exact settled position
            newNode.x  = oldNode.x;
            newNode.y  = oldNode.y;
            newNode.vx = oldNode.vx;
            newNode.vy = oldNode.vy;
          } else {
            // Brand new node — seed at the cluster's frozen anchor position
            newNode.x  = anchorX;
            newNode.y  = anchorY;
            newNode.vx = 0;
            newNode.vy = 0;
          }
          return newNode;
        });

        this.edgesData = data.edges;
        this.nodeCount = data.nodeCount;
        this.edgeCount = data.edgeCount;
        this.viewState = this.nodeCount === 0 ? 'empty' : 'loaded';
        this.cdr.detectChanges();

        // ── Step 3: Hot-update the render — preserving positions, not restarting simulation.
        this.renderGraph(this.nodesData, this.edgesData, true);

        // ── Step 4: Zoom to the frozen anchor coordinates.
        // Since we use graph-space coords (not screen-space), this is immune to
        // any camera transform already applied by the user.
        if (anchorX !== undefined && anchorY !== undefined) {
          setTimeout(() => this.zoomToNode({ x: anchorX, y: anchorY }, 0.75), 80);
        }
      },
      error: () => {
        this.viewState = 'error';
        this.errorMessage = 'Failed to expand cluster.';
        this.cdr.detectChanges();
      }
    });
  }

  loadMap(resetCameraAfterLoad: boolean = false) {
    this.viewState = 'loading';
    this.errorMessage = '';
    const previousSelection = this.selectedNode;
    this.dataService.loadMap().subscribe({
      next: (data) => {
        this.lastUpdated = new Date().toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
        
        // Preserve D3 physics coordinates across updates to prevent shuffling
        const oldNodesMap = new Map(this.nodesData.map((n: any) => [n.id, n]));
        this.nodesData = data.nodes.map((newNode: any) => {
          const oldNode = oldNodesMap.get(newNode.id);
          if (oldNode) {
            newNode.x = oldNode.x;
            newNode.y = oldNode.y;
            newNode.vx = oldNode.vx;
            newNode.vy = oldNode.vy;
          }
          return newNode;
        });
        
        this.edgesData = data.edges;
        this.nodeCount = data.nodeCount;
        this.edgeCount = data.edgeCount;
        this.viewState = this.nodeCount === 0 ? 'empty' : 'loaded';
        
        if (previousSelection) {
           this.selectedNode = this.nodesData.find((n: any) => n.id === previousSelection.id) || previousSelection;
        }

        this.cdr.detectChanges();
        setTimeout(() => {
           this.renderGraph(this.nodesData, this.edgesData);
           if (resetCameraAfterLoad) {
               setTimeout(() => this.resetCamera(), 50);
           }
        }, 100);
      },
      error: (err) => {
        this.viewState = 'error';
        this.errorMessage = 'Failed to load network topology.';
        this.cdr.detectChanges();
      },
    });
  }

  loadFocusMode(ip: string) {
    this.viewState = 'loading';
    this.errorMessage = '';
    const previousSelection = this.selectedNode;
    this.dataService.loadFocusMode(ip).subscribe({
      next: (data) => {
        this.lastUpdated = new Date().toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });

        // Preserve D3 physics coordinates across updates to prevent shuffling
        const oldNodesMap = new Map(this.nodesData.map((n: any) => [n.id, n]));
        this.nodesData = data.nodes.map((newNode: any) => {
          const oldNode = oldNodesMap.get(newNode.id);
          if (oldNode) {
            newNode.x = oldNode.x;
            newNode.y = oldNode.y;
            newNode.vx = oldNode.vx;
            newNode.vy = oldNode.vy;
          }
          return newNode;
        });

        this.edgesData = data.edges;
        this.nodeCount = data.nodeCount;
        this.edgeCount = data.edgeCount;
        this.viewState = this.nodeCount === 0 ? 'empty' : 'loaded';

        if (previousSelection) {
           this.selectedNode = this.nodesData.find((n: any) => n.id === previousSelection.id) || previousSelection;
        }

        this.cdr.detectChanges();
        setTimeout(() => {
           // Hot-update the simulation so preserved node coordinates aren't scattered
           this.renderGraph(this.nodesData, this.edgesData, true);
           
           // Zoom to the focused node if it exists, otherwise reset camera
           const focusedNode = this.nodesData.find((n: any) => n.id === ip);
           if (focusedNode && focusedNode.x !== undefined && focusedNode.y !== undefined) {
             this.zoomToNode(focusedNode, 1.2);
           } else {
             this.resetCamera();
           }
        }, 100);
      },
      error: (err) => {
        this.viewState = 'error';
        this.errorMessage = 'Failed to load specific node data.';
        this.cdr.detectChanges();
      },
    });
  }

  resetCamera() {
    if (!this.zoomBehavior || !this.svgRef) return;
    const svgEl = this.svgRef.nativeElement;
    const svg = d3.select(svgEl);
    
    const width = svgEl.clientWidth || 1000;
    const height = svgEl.clientHeight || 600;

    let targetScale = 1;
    if (this.nodeCount > 50) targetScale = 0.3;
    else if (this.nodeCount > 20) targetScale = 0.5;
    else targetScale = 0.8;

    if (this.previewMode) {
      targetScale *= 0.55;
    }

    const transform = d3.zoomIdentity
        .translate(width / 2 * (1 - targetScale), height / 2 * (1 - targetScale))
        .scale(targetScale);

    svg.transition().duration(750).call(this.zoomBehavior.transform, transform);
  }


  renderGraph(nodes: any[], edges: any[], isClusterExpand: boolean = false) {
    const svgEl = this.svgRef.nativeElement;
    const svg = d3.select(svgEl);

    const width = svgEl.clientWidth || 1000;
    const height = svgEl.clientHeight || 600;

    let g = svg.select<SVGGElement>('g.main-container');
    if (g.empty()) {
      const defs = svg.append('defs');

      const addGlow = (id: string, color: string) => {
        const filter = defs.append('filter').attr('id', id).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
        filter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
        filter.append('feComponentTransfer').attr('in', 'blur').attr('result', 'glow')
          .append('feFuncA').attr('type', 'linear').attr('slope', '1.5');
        const feMerge = filter.append('feMerge');
        feMerge.append('feMergeNode').attr('in', 'glow');
        feMerge.append('feMergeNode').attr('in', 'SourceGraphic');
      };

      addGlow('glow-cyan', '#00ccff');
      addGlow('glow-gold', '#ffcc00');
      addGlow('glow-green', '#00ff66');

      const shadow = defs.append('filter').attr('id', 'btn-shadow');
      shadow.append('feDropShadow').attr('dx', '0').attr('dy', '4').attr('stdDeviation', '4').attr('flood-color', '#000000').attr('flood-opacity', '0.8');

      const addGrad = (id: string, c1: string, c2: string) => {
        const grad = defs.append('linearGradient').attr('id', id).attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
        grad.append('stop').attr('offset', '0%').attr('stop-color', c1);
        grad.append('stop').attr('offset', '100%').attr('stop-color', c2);
      };
      
      addGrad('grad-cyan', '#0055ff', '#002288');
      addGrad('grad-gold', '#ffaa00', '#aa5500');
      addGrad('grad-green', '#00ff66', '#006622');

      const addArrow = (id: string, color: string) => {
        defs.append('marker')
          .attr('id', id)
          .attr('viewBox', '0 -5 10 10')
          .attr('refX', 30)
          .attr('refY', 0)
          .attr('markerWidth', 7)
          .attr('markerHeight', 7)
          .attr('orient', 'auto')
          .append('path')
          .attr('d', 'M0,-5L10,0L0,5')
          .attr('fill', color);
      };
      addArrow('arrow-cyan', '#00ccff');
      addArrow('arrow-gold', '#ffcc00');

      g = svg.append('g').attr('class', 'main-container');
      
      this.zoomBehavior = d3
          .zoom<SVGSVGElement, unknown>()
          .scaleExtent([0.1, 8])
          .on('zoom', (event) => {
             g.attr('transform', event.transform);
             svg.classed('zoomed-out', event.transform.k < 0.6);
          });
          
      svg.call(this.zoomBehavior);

      g.append('g').attr('class', 'links-layer');
      g.append('g').attr('class', 'labels-layer');
      g.append('g').attr('class', 'nodes-layer');
    }

    const linksLayer = g.select('.links-layer');
    const labelsLayer = g.select('.labels-layer');
    const nodesLayer = g.select('.nodes-layer');

    const link = linksLayer
      .selectAll<SVGGElement, any>('g.edge-group')
      .data(edges, (d: any) => `${d.source.id || d.source}-${d.target.id || d.target}`)
      .join(
        enter => {
          const eg = enter.append('g')
            .attr('class', 'edge-group')
            .style('opacity', (d: any) => {
               if (!this.isSearchActive) return 1;
               const s = d.source?.id || d.source;
               const t = d.target?.id || d.target;
               return (this.searchMatches.has(s) || this.searchMatches.has(t)) ? 1 : 0.15;
            });
            
          eg.append('line')
            .attr('class', 'base-link')
            .attr('stroke', (d: any) => {
               const w = Math.log((d.connections || 1) + 1);
               return w > 3 ? '#ffaa00' : '#0077ff';
            })
            .attr('stroke-width', (d: any) => Math.min(Math.log((d.connections || 1) + 1) * 2, 8))
            .attr('stroke-linecap', 'round')
            .attr('marker-end', (d: any) => {
               const w = Math.log((d.connections || 1) + 1);
               return w > 3 ? 'url(#arrow-gold)' : 'url(#arrow-cyan)';
            });

          eg.append('line')
            .attr('class', 'beaded-link')
            .attr('stroke', (d: any) => {
               const w = Math.log((d.connections || 1) + 1);
               return w > 3 ? '#ffeebb' : '#aaddff';
            })
            .attr('stroke-width', (d: any) => Math.min(Math.log((d.connections || 1) + 1) * 2, 8))
            .attr('stroke-dasharray', '2, 8')
            .attr('stroke-linecap', 'round')
            .style('display', (d: any) => {
               const w = Math.log((d.connections || 1) + 1);
               return w > 3 ? 'block' : 'none';
            });
            
          return eg;
        },
        update => {
          update.style('opacity', (d: any) => {
             if (!this.isSearchActive) return 1;
             const s = d.source?.id || d.source;
             const t = d.target?.id || d.target;
             return (this.searchMatches.has(s) || this.searchMatches.has(t)) ? 1 : 0.15;
          });
          return update;
        },
        exit => exit.remove()
      );

    const edgeLabel = labelsLayer
      .selectAll<SVGTextElement, any>('text')
      .data(edges.filter((d: any) => d.connections > 5), (d: any) => `${d.source.id || d.source}-${d.target.id || d.target}`)
      .join(
         enter => enter.append('text')
          .attr('fill', '#e2e8f0') // Clean white/gray
          .attr('font-size', '10px') 
          .attr('font-family', 'var(--font-sans)')
          .attr('font-weight', '500')
          .text((d: any) => d.connections)
          .style('opacity', (d: any) => {
             if (!this.isSearchActive) return 1;
             const s = d.source?.id || d.source;
             const t = d.target?.id || d.target;
             return (this.searchMatches.has(s) || this.searchMatches.has(t)) ? 1 : 0;
          }),
         update => {
          update.text((d: any) => d.connections)
                .style('opacity', (d: any) => {
                   if (!this.isSearchActive) return 1;
                   const s = d.source?.id || d.source;
                   const t = d.target?.id || d.target;
                   return (this.searchMatches.has(s) || this.searchMatches.has(t)) ? 1 : 0;
                });
          return update;
         },
         exit => exit.remove()
      );

    const node = nodesLayer
      .selectAll<SVGGElement, any>('g.topology-node')
      .data(nodes, (d: any) => d.id)
      .join(
        enter => {
          const nodeEnter = enter.append('g')
            .attr('class', (d: any) => {
               let base = `topology-node node-${d.id.replace(/[^a-zA-Z0-9_-]/g, '-')} ${this.getNodeTypeClass(d)}`;
               if (this.selectedNode && this.selectedNode.id === d.id) base += ' is-selected';
               if (this.isSearchActive && this.searchMatches.has(d.id)) base += ' search-match';
               return base;
            })
            .style('cursor', 'pointer')
            .style('opacity', 0)
            .call(this.physics.dragBehavior)
            .on('click', (event, d: any) => {
              if (d.type === 'cluster' && !this.focusMode) {
                  this.expandCluster(d);
                  return;
              }
              this.selectedNode = d;
              nodesLayer.selectAll('.topology-node').classed('is-selected', (n: any) => n.id === d.id);
              if (this.focusMode) {
                this.applyFocus();
              }
              this.cdr.detectChanges();
            })
            .on('mouseover', function(event, d) {
              d3.select(this).raise(); // Bring node to front when hovered
            });

          // Base rim (dark blue/black)
          nodeEnter.append('circle')
            .attr('class', 'node-rim')
            .attr('r', (d: any) => {
               const base = d.type === 'cluster' ? 24 : (d.is_internal ? 20 : 16);
               const bonus = Math.min(Math.log((d.connections || 0) + 1) * 3, 15);
               return base + bonus + 6;
            })
            .attr('fill', '#040b16')
            .attr('stroke', '#0044aa')
            .attr('stroke-width', 1.5)
            .attr('filter', 'url(#btn-shadow)');

          // Inner colored core
          nodeEnter.append('circle')
            .attr('class', 'node-core')
            .attr('r', (d: any) => {
               const base = d.type === 'cluster' ? 24 : (d.is_internal ? 20 : 16);
               const bonus = Math.min(Math.log((d.connections || 0) + 1) * 3, 15);
               return base + bonus;
            })
            .attr('fill', (d: any) => {
               if (d.threat) return 'url(#grad-gold)';
               return d.is_internal ? 'url(#grad-green)' : 'url(#grad-cyan)';
            })
            .attr('stroke', (d: any) => {
               if (d.threat) return '#ffeebb';
               return d.is_internal ? '#ccffdd' : '#aaddff';
            })
            .attr('stroke-width', 2);

          nodeEnter.append('path')
            .attr('d', (d: any) => this.getNodeIconPath(d))
            .attr('transform', (d: any) => (d.type === 'cluster' ? 'translate(-12, -12) scale(1)' : 'translate(-9, -9) scale(0.75)'))
            .attr('fill', 'none')
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 1.5)
            .attr('stroke-linecap', 'round')
            .attr('stroke-linejoin', 'round')
            .style('display', (d: any) => (this.hasFavicon(d) ? 'none' : 'block'));

          nodeEnter.append('image')
            .attr('href', (d: any) => this.hasFavicon(d) ? `/favicon-proxy?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${this.getDomain(d)}&size=64` : '')
            .attr('width', 20)
            .attr('height', 20)
            .attr('x', -10)
            .attr('y', -10)
            .style('display', (d: any) => (this.hasFavicon(d) ? 'block' : 'none'))
            .on('error', function() {
              d3.select(this as SVGImageElement).style('display', 'none');
              d3.select((this as SVGImageElement).parentNode as SVGGElement).select('path').style('display', 'block');
            });

          nodeEnter.append('text')
            .attr('text-anchor', 'middle')
            .attr('y', 36)
            .attr('fill', '#ffffff')
            .attr('font-size', '11.5px')
            .attr('font-family', 'var(--font-sans)')
            .attr('font-weight', '700')
            .text((d: any) => {
              const t = d.label || d.id;
              if (t.length > 20) return t.substring(0, 18) + '...';
              return t;
            });

          nodeEnter.append('text')
            .attr('text-anchor', 'middle')
            .attr('y', 50)
            .attr('fill', '#71717a') // Muted gray
            .attr('font-size', '10px')
            .attr('font-family', 'var(--font-sans)')
            .text((d: any) => {
                if (d.type === 'cluster') return '';
                return d.type && d.type !== 'unknown' ? d.type : (d.is_internal ? 'internal' : 'external');
            });

          nodeEnter.filter((d: any) => (d.connections || 0) > 0)
            .append('text')
            .attr('class', 'connection-count')
            .attr('x', 18)
            .attr('y', -18)
            .attr('text-anchor', 'middle')
            .attr('fill', '#e2e8f0') 
            .attr('font-size', '10px') 
            .attr('font-family', 'var(--font-sans)')
            .attr('font-weight', '600')
            .text((d: any) => (d.connections > 0 ? `${d.connections}` : ''));

          nodeEnter.transition().duration(500).style('opacity', (d: any) => {
             if (!this.isSearchActive) return 1;
             return this.searchMatches.has(d.id) ? 1 : 0.15;
          });
          return nodeEnter;
        },
        update => {
          update.attr('class', (d: any) => {
             let base = `topology-node node-${d.id.replace(/[^a-zA-Z0-9_-]/g, '-')} ${this.getNodeTypeClass(d)}`;
             if (this.selectedNode && this.selectedNode.id === d.id) base += ' is-selected';
             if (this.isSearchActive && this.searchMatches.has(d.id)) base += ' search-match';
             return base;
          });
          
          update.style('opacity', (d: any) => {
             if (!this.isSearchActive) return 1;
             return this.searchMatches.has(d.id) ? 1 : 0.15;
          });
          
          // Ensure dynamic elements update if data changes mid-session
          update.select('.node-rim')
            .attr('r', (d: any) => {
               const base = d.type === 'cluster' ? 24 : (d.is_internal ? 20 : 16);
               const bonus = Math.min(Math.log((d.connections || 0) + 1) * 3, 15);
               return base + bonus + 6;
            });
          update.select('.node-core')
            .attr('r', (d: any) => {
               const base = d.type === 'cluster' ? 24 : (d.is_internal ? 20 : 16);
               const bonus = Math.min(Math.log((d.connections || 0) + 1) * 3, 15);
               return base + bonus;
            });

          update.select('path')
            .attr('d', (d: any) => this.getNodeIconPath(d))
            .style('display', (d: any) => (this.hasFavicon(d) ? 'none' : 'block'));

          update.select('image')
            .attr('href', (d: any) => this.hasFavicon(d) ? `/favicon-proxy?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${this.getDomain(d)}&size=64` : '')
            .style('display', (d: any) => (this.hasFavicon(d) ? 'block' : 'none'));

          update.select('.connection-count')
            .text((d: any) => (d.connections > 0 ? `${d.connections}` : ''));

          return update;
        },
        exit => exit.transition().duration(500).style('opacity', 0).remove()
      );

    const tickFn = () => {
      link.select('.base-link')
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);
        
      link.select('.beaded-link')
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      edgeLabel
        .attr('x', (d: any) => (d.source.x + d.target.x) / 2)
        .attr('y', (d: any) => (d.source.y + d.target.y) / 2);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    };

    if (isClusterExpand) {
      // Hot-path: update the existing simulation in-place.
      // Old nodes keep their settled positions; only new nodes (seeded at anchor) drift outward.
      this.physics.updateSimulation(nodes, edges, tickFn);
    } else {
      // Cold-path: full restart (initial load, focus mode, manual refresh).
      this.physics.initSimulation(nodes, edges, width, height, tickFn);
    }
  }
}
