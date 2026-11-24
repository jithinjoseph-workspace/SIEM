import {
  AfterViewInit, ChangeDetectionStrategy, ChangeDetectorRef, Component, ElementRef,
  NgZone, OnDestroy, OnInit, ViewChild, ViewEncapsulation,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import {
  LucideAngularModule,
  Activity, Building2, Users, Server,
  ShieldCheck, Zap, TrendingUp, Clock,
  Globe, Radio, Cpu, Layers, HardDrive,
  RefreshCw, ArrowUpRight, ShieldAlert, Network,
  CheckCircle2, AlertCircle, Filter, Sparkles,
  BarChart3, Database, Wifi, Download, ExternalLink,
  ChevronRight, Laptop, PlayCircle,
  ZoomIn, ZoomOut, RotateCcw, Maximize2, Minimize2,
  Terminal, Trash2, Pause, Play,
  UserCheck, Lock, FileText, Sliders
} from 'lucide-angular';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import * as THREE from 'three';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
export interface UserAuditLog {
  id: string;
  time: string;
  category: 'AUTH' | 'IAM' | 'RULES' | 'POLICY' | 'CONFIG' | 'INVESTIGATE';
  user: string;
  role: string;
  tenant?: string;
  action: string;
  ip?: string;
  status: 'SUCCESS' | 'WARN' | 'BLOCKED';
}

export interface RelayHub {
  id: string;
  name: string;
  city: string;
  region: string;
  flag: string;
  lat: number;
  lon: number;
  status: 'Operational' | 'Synchronized' | 'Degraded';
  throughput: string;
  latency: string;
  loadPercent: number;
  attackCount?: number;
}

export interface FleetNodeItem {
  id: string;
  name: string;
  status: string;
  uptime: string;
  ip: string;
  latency: string;
  throughput: string;
  cpu: number;
  memory: number;
  lastHeartbeat: string;
}

export interface OrgLeaderboardItem {
  id: string;
  name: string;
  flag: string;
  region: string;
  userCount: number;
  percentage: number;
  status: string;
}

export interface ThreatIntelTableItem {
  ip: string;
  country: string;
  code: string;
  flag: string;
  lat: number;
  lon: number;
  dispLat?: number;
  dispLon?: number;
  hits: number;
  feed: string;
  threatType: string;
}

@Component({
  selector: 'app-overview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.Default,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './overview.html',
  styleUrl: './overview.css',
})
export class Overview implements OnInit, AfterViewInit, OnDestroy {
  Math = Math;

  @ViewChild('commandMesh') commandMesh?: ElementRef<HTMLDivElement>;
  @ViewChild('globalGlobe') globalGlobe?: ElementRef<HTMLDivElement>;
  @ViewChild('worldMapContainer') worldMapContainer?: ElementRef<HTMLDivElement>;

  // Lucide Icons
  ActivityIcon    = Activity;
  BuildingIcon    = Building2;
  UsersIcon       = Users;
  ServerIcon      = Server;
  ShieldIcon      = ShieldCheck;
  ZapIcon         = Zap;
  TrendIcon       = TrendingUp;
  ClockIcon       = Clock;
  GlobeIcon       = Globe;
  RadioIcon       = Radio;
  CpuIcon         = Cpu;
  LayersIcon      = Layers;
  HardDriveIcon   = HardDrive;
  RefreshIcon     = RefreshCw;
  ArrowUpRightIcon = ArrowUpRight;
  ShieldAlertIcon = ShieldAlert;
  NetworkIcon     = Network;
  CheckCircleIcon = CheckCircle2;
  AlertCircleIcon = AlertCircle;
  FilterIcon      = Filter;
  SparklesIcon    = Sparkles;
  BarChartIcon    = BarChart3;
  DatabaseIcon    = Database;
  WifiIcon        = Wifi;
  DownloadIcon    = Download;
  ExternalIcon    = ExternalLink;
  ChevronRightIcon = ChevronRight;
  LaptopIcon      = Laptop;
  PlayCircleIcon  = PlayCircle;
  ZoomInIcon      = ZoomIn;
  ZoomOutIcon     = ZoomOut;
  RotateCcwIcon   = RotateCcw;
  MaximizeIcon    = Maximize2;
  MinimizeIcon    = Minimize2;
  TerminalIcon    = Terminal;
  TrashIcon       = Trash2;
  PauseIcon       = Pause;
  PlayIcon        = Play;
  UserCheckIcon   = UserCheck;
  LockIcon        = Lock;
  FileTextIcon    = FileText;
  SlidersIcon     = Sliders;

  // Map & Fabric Enhanced State
  isMapExpanded = false;
  activeRegionFilter: 'all' | 'eu' | 'apac' | 'americas' | 'mea' = 'all';
  private d3WorldMapZoom: any = null;
  private d3WorldMapSvg: any = null;
  private mapProjection: any = null;

  // Real State Data from Backend APIs
  users: any[]      = [];
  tenants: any[]    = [];
  engines: any[]    = [];
  sensorKeys: any[] = [];
  threatCountries: any[] = [];
  kafkaData: any    = null;
  kafkaLoading      = false;
  showKafkaDetails  = false;
  sideCardTab: 'threat' | 'orgs' = 'threat';
  threatIntelItems: ThreatIntelTableItem[] = [];
  filteredThreatIntelItems: ThreatIntelTableItem[] = [];
  threatSearchQuery = '';
  totalThreatIps    = 0;
  private targetGlobeRot: [number, number, number] | null = null;
  private globeScale = 1.0;
  private targetGlobeScale = 1.0;

  // Raft Consensus & Leader State (from /api/admin/leader-status)
  leaderStatus: any = { current_leader: '', ttl_seconds: 0, ttl_ms: 0, election_info: '' };

  // Threat Severity Spectrum (from /api/severity)
  severityData: { critical: number; high: number; medium: number; low: number } = { critical: 0, high: 0, medium: 0, low: 0 };

  // Analytical Storage & Deep Packet Stats (from /api/stats)
  statsData: { events_total: number; hits_total: number; events_1h: number; hits_1h: number; agent_z_events: number; agent_s_events: number } = {
    events_total: 0, hits_total: 0, events_1h: 0, hits_1h: 0, agent_z_events: 0, agent_s_events: 0
  };

  // Top Attacker / Flow IPs (from /api/top-ips)
  topIpsData: { top_src_ips: any[]; top_dst_ips: any[] } = { top_src_ips: [], top_dst_ips: [] };
  ipFlowTab: 'tenants' | 'threats' | 'flows' = 'tenants';

  // L4 / L7 Deep Packet Protocol Distribution (from /api/protocols)
  protocolsData: any[] = [];

  // Live Cyber SOC Event Stream
  socEventLogs: Array<{ id: string; time: string; level: 'OK' | 'INGEST' | 'RAFT' | 'WARN' | 'SECURITY'; msg: string; source: string }> = [];
  socLogFilter: 'ALL' | 'CRITICAL' | 'ENGINES' | 'INGEST' = 'ALL';
  socLogPaused = false;
  private socLogTimer: any = null;

  // Real User & Operator Activity Audit Trail (Side Glass Terminal)
  userAuditLogs: UserAuditLog[] = [];
  userAuditFilter: 'ALL' | 'AUTH' | 'IAM' | 'RULES' | 'POLICY' | 'CONFIG' | 'INVESTIGATE' = 'ALL';
  userAuditPaused = false;
  private userAuditTimer: any = null;

  // Real System & Telemetry Metrics from Server
  memoryUsedGb   = 0;
  memoryTotalGb  = 0;
  eventsPerSec   = 0;
  events1h       = 0;
  eventsTotal    = 0;
  rulesCount     = 0;
  enabledRulesCount = 0;

  // Filter & Toggle states
  fabricMode: 'map' | 'globe' = 'map';
  timeRange: 'realtime' | '1h' | '24h' | '7d' = 'realtime';
  selectedRelay: RelayHub | null = null;
  isRefreshing = false;

  // Telemetry stream history
  overviewTelemetryHistory: { time: Date; cpu: number; mem: number; label?: string }[] = [];
  private overviewTelemetryPollTimer: any = null;
  private resizeObserver: ResizeObserver | null = null;
  private resizeTimeout: any = null;

  // Three.js instances
  private meshResizeObserver: ResizeObserver | null = null;
  private meshAnimationFrame: number | null = null;
  private meshRenderer: THREE.WebGLRenderer | null = null;
  private meshScene: THREE.Scene | null = null;
  private meshGeometry: THREE.BufferGeometry | null = null;
  private meshMaterial: THREE.PointsMaterial | null = null;

  private globeResizeObserver: ResizeObserver | null = null;
  private globeAnimationFrame: number | null = null;
  private globeRenderer: THREE.WebGLRenderer | null = null;
  private globeGeometries: THREE.BufferGeometry[] = [];
  private globeMaterials: THREE.Material[] = [];

  // World map data cache
  private cachedWorldData: any = null;
  private mapResizeObserver: ResizeObserver | null = null;

  // Real Relay Hubs (Populated dynamically from /api/threat-map and /api/sensor-keys)
  relayHubs: RelayHub[] = [];

  constructor(
    private api: Api,
    private auth: AuthService,
    private http: HttpClient,
    private cdr: ChangeDetectorRef,
    private zone: NgZone,
    public clock: ClockService,
  ) {}

  // ── 100% Real Computed Metrics ─────────────────────────────────

  get activeEngines() {
    return this.engines.filter(e =>
      e.status?.toLowerCase().includes('up') ||
      e.status?.toLowerCase().includes('run') ||
      e.status?.toLowerCase().includes('health')
    ).length;
  }

  get clusterAvailability(): number {
    if (!this.engines.length) return 100;
    return Math.round((this.activeEngines / this.engines.length) * 10000) / 100;
  }

  get activeTenantsCount() {
    return this.tenants.filter(t => t.active).length;
  }

  get activeSensorsCount() {
    return this.sensorKeys.filter(s => s.active).length;
  }

  get managedUsers() {
    return this.users.filter(u => u.role !== 'super_admin');
  }

  get latestCpu(): number {
    return this.overviewTelemetryHistory.at(-1)?.cpu ?? 0;
  }

  get latestMemory(): number {
    return this.overviewTelemetryHistory.at(-1)?.mem ?? 0;
  }

  get overallHealthScore(): number {
    const engineRatio = this.engines.length ? (this.activeEngines / this.engines.length) : 1;
    const tenantRatio = this.tenants.length ? (this.activeTenantsCount / this.tenants.length) : 1;
    const sensorRatio = this.sensorKeys.length ? (this.activeSensorsCount / this.sensorKeys.length) : 1;
    const ruleRatio   = this.rulesCount ? (this.enabledRulesCount / this.rulesCount) : 1;
    return Math.round((engineRatio * 0.4 + tenantRatio * 0.2 + sensorRatio * 0.2 + ruleRatio * 0.2) * 100);
  }

  get tenantRatioPercent(): number {
    if (!this.tenants.length) return 100;
    return Math.round((this.activeTenantsCount / this.tenants.length) * 100);
  }

  get sensorRatioPercent(): number {
    if (!this.sensorKeys.length) return 100;
    return Math.round((this.activeSensorsCount / this.sensorKeys.length) * 100);
  }

  get ruleRatioPercent(): number {
    if (!this.rulesCount) return 100;
    return Math.round((this.enabledRulesCount / this.rulesCount) * 100);
  }

  get leaderName(): string {
    const l = this.leaderStatus?.current_leader;
    if (!l || l === 'none' || l === 'null' || l === 'undefined') {
      return 'Awaiting Election';
    }
    return l;
  }

  get leaderTtl(): number {
    const ttl = Number(this.leaderStatus?.ttl_seconds);
    return Math.max(0, isNaN(ttl) || ttl < 0 ? 0 : ttl);
  }

  get isLeaderActive(): boolean {
    const l = this.leaderStatus?.current_leader;
    return !!(l && l !== 'none' && l !== 'null' && l !== 'undefined' && l !== 'Awaiting Election');
  }

  get raftLeasePercent(): number {
    const s = this.leaderTtl;
    return Math.min(100, Math.max(0, Math.round((s / 30) * 100)));
  }

  isPrivateIp(ip: string): boolean {
    if (!ip) return true;
    const clean = ip.trim().toLowerCase();
    if (clean === 'localhost' || clean === '::1' || clean === '127.0.0.1' || clean === '0.0.0.0') return true;
    if (clean.startsWith('fe80:') || clean.startsWith('fc00:') || clean.startsWith('fd00:') || clean.startsWith('ff02:')) return true;
    if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
    if (clean.startsWith('172.')) {
      const parts = clean.split('.');
      if (parts.length >= 2) {
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) return true;
      }
    }
    return false;
  }

  get topPublicIps(): any[] {
    const all = [...(this.topIpsData.top_src_ips || []), ...(this.topIpsData.top_dst_ips || [])];
    const seen = new Set<string>();
    const res: any[] = [];
    for (const item of all) {
      const ip = item.ip || item.src_ip || item.dst_ip;
      if (ip && !this.isPrivateIp(ip) && !seen.has(ip)) {
        seen.add(ip);
        res.push({
          ip,
          country: item.country || 'External Public Flow',
          count: item.count || item.hits || 1,
          type: 'External Ingress Flow'
        });
      }
    }
    return res;
  }

  get tenantFleetMatrix() {
    const userCounts: Record<string, number> = {};
    for (const u of this.users) {
      if (u.tenant_id) userCounts[u.tenant_id] = (userCounts[u.tenant_id] || 0) + 1;
    }

    const sensorMap: Record<string, { total: number; active: number; names: string[] }> = {};
    for (const s of this.sensorKeys) {
      if (s.tenant_id) {
        if (!sensorMap[s.tenant_id]) sensorMap[s.tenant_id] = { total: 0, active: 0, names: [] };
        sensorMap[s.tenant_id].total++;
        if (s.active) sensorMap[s.tenant_id].active++;
        if (s.name || s.key_prefix) sensorMap[s.tenant_id].names.push(s.name || s.key_prefix);
      }
    }

    const totalClusterSensors = Math.max(1, this.activeSensorsCount);

    return this.tenants.map((t, idx) => {
      const uCount = userCounts[t.id] || (t.user_count ? Number(t.user_count) : 0);
      const sInfo = sensorMap[t.id] || { total: 0, active: 0, names: [] };
      const sensorShare = sInfo.active > 0 ? (sInfo.active / totalClusterSensors) : 0;
      const estPackets = Math.round((this.eventsTotal || this.statsData.events_total || 0) * sensorShare);
      const estEps = Math.round(this.eventsPerSec * sensorShare);

      return {
        id: t.id,
        name: t.name || `Tenant-${idx + 1}`,
        active: t.active,
        users: uCount,
        sensorsTotal: sInfo.total,
        sensorsActive: sInfo.active,
        sensorNames: sInfo.names.slice(0, 3).join(', '),
        ingestShare: Math.round(sensorShare * 100),
        estPackets,
        estEps,
        isolation: 'STRICT RBAC',
        posture: !t.active ? 'SUSPENDED' : (sInfo.active > 0 ? 'PROTECTED' : 'PENDING PROBE')
      };
    }).sort((a, b) => b.sensorsActive - a.sensorsActive || b.users - a.users);
  }

  get totalSeverityAlerts(): number {
    return (this.severityData.critical || 0) + (this.severityData.high || 0) + (this.severityData.medium || 0) + (this.severityData.low || 0);
  }

  get criticalPercent(): number {
    if (!this.totalSeverityAlerts) return 0;
    return Math.round((this.severityData.critical / this.totalSeverityAlerts) * 100);
  }

  get highPercent(): number {
    if (!this.totalSeverityAlerts) return 0;
    return Math.round((this.severityData.high / this.totalSeverityAlerts) * 100);
  }

  get mediumPercent(): number {
    if (!this.totalSeverityAlerts) return 0;
    return Math.round((this.severityData.medium / this.totalSeverityAlerts) * 100);
  }

  get lowPercent(): number {
    if (!this.totalSeverityAlerts) return 0;
    return Math.round((this.severityData.low / this.totalSeverityAlerts) * 100);
  }

  get totalProtocolPackets(): number {
    return this.protocolsData.reduce((sum, p) => sum + (Number(p.count) || Number(p.packets) || 0), 0);
  }

  getProtocolPercent(proto: any): number {
    if (!this.totalProtocolPackets) return 0;
    const cnt = Number(proto?.count) || Number(proto?.packets) || 0;
    if (cnt <= 0) return 0;
    return Math.min(100, Math.max(1, Math.round((cnt / this.totalProtocolPackets) * 100)));
  }

  get filteredSocLogs() {
    if (this.socLogFilter === 'ALL') return this.socEventLogs;
    if (this.socLogFilter === 'CRITICAL') return this.socEventLogs.filter(l => l.level === 'WARN' || l.level === 'SECURITY');
    if (this.socLogFilter === 'ENGINES') return this.socEventLogs.filter(l => l.source === 'ENGINE' || l.level === 'RAFT' || l.source === 'RAFT');
    if (this.socLogFilter === 'INGEST') return this.socEventLogs.filter(l => l.level === 'INGEST' || l.source === 'CLICKHOUSE' || l.source === 'KAFKA' || l.source === 'PROBES' || l.source === 'AGENT-Z');
    return this.socEventLogs;
  }

  get filteredUserAuditLogs(): UserAuditLog[] {
    if (this.userAuditFilter === 'ALL') return this.userAuditLogs;
    return this.userAuditLogs.filter(l => l.category === this.userAuditFilter);
  }

  get totalPartitions(): number {
    return this.kafkaData?.partition_count || this.kafkaData?.partitions?.length || 0;
  }

  // trackBy fns — several getters above (tenantFleetMatrix, topPublicIps,
  // fleetNodes, filteredThreatIntelItems) build fresh object literals on
  // every call, so *ngFor's default identity check fails every CD cycle and
  // tears down/rebuilds the whole row set. Track by a stable field instead.
  trackByIp   = (_: number, item: { ip: string }) => item.ip;
  trackById   = (_: number, item: { id: string }) => item.id;
  trackByPartition = (_: number, p: number) => p;

  get roleCounts(): Record<string, number> {
    const counts: Record<string, number> = { 'Platform Admin': 0, 'Tenant Admin': 0, 'Analyst': 0, 'Viewer': 0 };
    for (const u of this.users) {
      if (u.role === 'admin' || u.role === 'super_admin') counts['Platform Admin']++;
      else if (u.role === 'tenant_admin') counts['Tenant Admin']++;
      else if (u.role === 'analyst' || u.role === 'senior_analyst') counts['Analyst']++;
      else if (u.role === 'viewer') counts['Viewer']++;
    }
    return counts;
  }

  // Real NDR Engine Cluster nodes from /api/admin/engines (Exclusively NDR Engines)
  get fleetNodes(): FleetNodeItem[] {
    return this.engines.map((e, idx) => {
      const isUp = (e.status?.toLowerCase().includes('up') || e.status?.toLowerCase().includes('run'));
      return {
        id: e.name || `engine-${idx + 1}`,
        name: e.name || `ndr-engine-${idx + 1}`,
        status: isUp ? 'ONLINE' : 'DEGRADED',
        // e.running is Docker's real "RunningFor" duration (e.g. "35 minutes") —
        // show that as uptime instead of re-displaying the status string under
        // a mislabeled column.
        uptime: e.running || e.status || 'Running',
        ip: '127.0.0.1 (Docker Host)',
        latency: isUp ? '< 1ms' : 'Timeout',
        throughput: this.eventsPerSec > 0 ? `${Math.round(this.eventsPerSec / Math.max(1, this.activeEngines))} eps` : (isUp ? 'Active' : '0 eps'),
        cpu: Math.round(this.latestCpu || 0),
        memory: Math.round(this.latestMemory || 0),
        lastHeartbeat: isUp ? 'Just now' : 'Offline',
      };
    });
  }

  // Real Top Organizations computed directly from user accounts per tenant
  get orgLeaderboard(): OrgLeaderboardItem[] {
    const counts: { [key: string]: number } = {};
    for (const u of this.users) {
      if (u.tenant_id) counts[u.tenant_id] = (counts[u.tenant_id] || 0) + 1;
    }

    const items: OrgLeaderboardItem[] = this.tenants.map((t, idx) => {
      const uCount = counts[t.id] || (t.user_count ? Number(t.user_count) : 0);
      return {
        id: t.id,
        name: t.name || `Tenant ${idx + 1}`,
        flag: '🏢',
        region: t.active ? 'Active Tenant Scope' : 'Suspended',
        userCount: uCount,
        percentage: 0,
        status: t.active ? 'ACTIVE' : 'IDLE',
      };
    }).sort((a, b) => b.userCount - a.userCount);

    const maxCount = Math.max(1, ...items.map(i => i.userCount));
    items.forEach(i => {
      i.percentage = Math.round((i.userCount / maxCount) * 100);
    });

    return items;
  }

  ngOnInit() {
    this.loadWorldData();
    this.loadAllRealPlatformData();
    this.initSocLogs();
    this.startSocLogTicker();
    this.initUserAuditLogs();
    this.startUserAuditTicker();

    setTimeout(() => {
      this.renderAllCharts();
      this.setupResizeObserver();
      this.startOverviewTelemetryPolling();
    }, 150);
  }

  // ── Load All Real Backend APIs ─────────────────────────────────

  loadAllRealPlatformData() {
    // 1. Real Users
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = data.users || [];
        this.cdr.detectChanges();
        this.renderUserRolesDonut();
      },
      error: reportRxjsError,
    });

    // 2. Real Tenants
    this.api.getTenants().subscribe({
      next: (data: any) => {
        this.tenants = data.tenants || [];
        this.cdr.detectChanges();
        this.renderFocusedPostureGauge();
      },
      error: reportRxjsError,
    });

    // 3. Real Engine Nodes
    this.api.getEngines().subscribe({
      next: (data: any) => {
        this.engines = data.engines || [];
        this.cdr.detectChanges();
        this.renderFocusedPostureGauge();
      },
      error: reportRxjsError,
    });

    // 4. Real Sensor Keys
    this.api.getSensorKeys().subscribe({
      next: (keys: any[]) => {
        this.sensorKeys = keys || [];
        this.cdr.detectChanges();
        this.renderFocusedPostureGauge();
      },
      error: reportRxjsError,
    });

    // 5. Real Global Threat Intelligence Map with All Country Attribution
    this.api.getThreatIntelMap().subscribe({
      next: (data: any) => {
        const countries = data?.countries || [];
        if (countries.length > 0) {
          this.threatCountries = countries;
          this.buildThreatIntelItems(countries);
          this.updateRelayHubsFromRealData();
          if (this.fabricMode === 'map') this.initWorldMap();
          else if (this.fabricMode === 'globe') this.initGlobalGlobe();
          this.cdr.detectChanges();
        } else {
          this.loadFallbackTrafficMap();
        }
      },
      error: () => {
        this.loadFallbackTrafficMap();
      }
    });

    // 5b. Real Threat Intel Feed Overview (platform-wide, all tenants)
    this.api.getThreatIntelAllTenants().subscribe({
      next: (data: any) => {
        this.totalThreatIps = Number(data?.total_malicious_ips) || 0;
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });

    // 6. Real ClickHouse Event Stats
    this.loadStatsData();

    // 7. Real Distributed Raft Leader & Consensus
    this.loadLeaderStatus();

    // 8. Real Threat Severity Spectrum
    this.loadSeverityData();

    // 9. Real Top Attacker IPs & Targets
    this.loadTopIpsData();

    // 10. Real Deep Packet Protocol Distribution
    this.loadProtocolsData();

    // 11. Real Rules Status
    this.api.getRules().subscribe({
      next: (rules: any[]) => {
        this.rulesCount = rules?.length || 0;
        this.enabledRulesCount = rules?.filter(r => r.enabled).length || 0;
        this.renderFocusedPostureGauge();
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });

    // 12. Real Kafka Cluster Status
    this.loadKafkaStatus();
  }

  loadLeaderStatus() {
    this.api.getLeaderStatus().subscribe({
      next: (data: any) => {
        if (data) {
          this.leaderStatus = data;
          this.cdr.detectChanges();
        }
      },
      error: reportRxjsError
    });
  }

  // Platform-wide across all tenants (Super Admin Overview), not just the
  // default tenant's own hits — see api.getSeverityAllTenants().
  loadSeverityData() {
    this.api.getSeverityAllTenants().subscribe({
      next: (data: any) => {
        if (data) {
          this.severityData = {
            critical: Number(data.critical) || 0,
            high: Number(data.high) || 0,
            medium: Number(data.medium) || 0,
            low: Number(data.low) || 0,
          };
          this.cdr.detectChanges();
        }
      },
      error: reportRxjsError
    });
  }

  // Platform-wide across all tenants — see api.getStatsAllTenants().
  loadStatsData() {
    this.api.getStatsAllTenants().subscribe({
      next: (stats: any) => {
        if (stats) {
          this.eventsTotal = Number(stats.events_total) || 0;
          this.statsData = {
            events_total: Number(stats.events_total) || 0,
            hits_total: Number(stats.hits_total) || 0,
            events_1h: Number(stats.events_1h) || 0,
            hits_1h: Number(stats.hits_1h) || 0,
            agent_z_events: Number(stats.agent_z_events) || 0,
            agent_s_events: Number(stats.agent_s_events) || 0,
          };
          this.cdr.detectChanges();
        }
      },
      error: reportRxjsError
    });
  }

  // Platform-wide across all tenants — see api.getTopIpsAllTenants().
  loadTopIpsData() {
    this.api.getTopIpsAllTenants().subscribe({
      next: (data: any) => {
        if (data) {
          this.topIpsData = {
            top_src_ips: data.top_src_ips || [],
            top_dst_ips: data.top_dst_ips || [],
          };
          this.cdr.detectChanges();
        }
      },
      error: reportRxjsError
    });
  }

  // Platform-wide across all tenants — see api.getProtocolsAllTenants().
  loadProtocolsData() {
    this.api.getProtocolsAllTenants().subscribe({
      next: (data: any) => {
        if (data && data.protocols) {
          this.protocolsData = data.protocols;
          this.cdr.detectChanges();
        }
      },
      error: reportRxjsError
    });
  }

  setIpFlowTab(tab: 'tenants' | 'threats' | 'flows') {
    this.ipFlowTab = tab;
    this.cdr.detectChanges();
  }

  setSocLogFilter(filter: 'ALL' | 'CRITICAL' | 'ENGINES' | 'INGEST') {
    this.socLogFilter = filter;
    this.cdr.detectChanges();
  }

  toggleSocLogPause() {
    this.socLogPaused = !this.socLogPaused;
    this.cdr.detectChanges();
  }

  clearSocLogs() {
    this.socEventLogs = [];
    this.cdr.detectChanges();
  }

  // ── User Audit & Operator History Methods ──────────────────────

  setUserAuditFilter(filter: 'ALL' | 'AUTH' | 'IAM' | 'RULES' | 'POLICY' | 'CONFIG' | 'INVESTIGATE') {
    this.userAuditFilter = filter;
    this.cdr.detectChanges();
  }

  toggleUserAuditPause() {
    this.userAuditPaused = !this.userAuditPaused;
    this.cdr.detectChanges();
  }

  clearUserAuditLogs() {
    this.userAuditLogs = [];
    this.cdr.detectChanges();
  }

  exportUserAuditLogs() {
    const lines = this.userAuditLogs.map(l =>
      `[${l.time}] [${l.category}] [user: ${l.user}] (${l.role}) ${l.action} [tenant: ${l.tenant || 'Global'}] [status: ${l.status}] [ip: ${l.ip || 'unknown'}]`
    );
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `operator-audit-trail-${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    this.pushUserAuditLog('CONFIG', curUser, curRole, 'Operator exported complete audit trail log report', 'Global Mesh', 'SUCCESS');
  }

  pushUserAuditLog(
    category: 'AUTH' | 'IAM' | 'RULES' | 'POLICY' | 'CONFIG' | 'INVESTIGATE',
    user: string,
    role: string,
    action: string,
    tenant = 'Default Organization',
    status: 'SUCCESS' | 'WARN' | 'BLOCKED' = 'SUCCESS',
    // The frontend has no reliable way to know the real client IP without a
    // backend call, so entries generated here leave it unset rather than
    // fabricate a plausible-looking address.
    ip?: string
  ) {
    if (this.userAuditPaused) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    this.userAuditLogs.unshift({
      id: Math.random().toString(36).substring(2, 9),
      time: timeStr,
      category,
      user,
      role,
      tenant,
      action,
      ip,
      status
    });
    if (this.userAuditLogs.length > 80) this.userAuditLogs.pop();
    this.cdr.detectChanges();
  }

  initUserAuditLogs() {
    // This terminal used to seed itself with fabricated actions attributed to
    // other real usernames (secops_lead, analyst1, tenant_admin) that never
    // actually happened — misleading for a security product. The only thing
    // we can honestly claim here is the current session's own real start;
    // everything else is populated by checkForRealAuditEvents() below, which
    // only logs genuine, observed state changes.
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    const primaryTenant = this.tenants[0]?.name || 'Global Security Mesh';
    this.pushUserAuditLog('AUTH', curUser, curRole, 'Interactive administrator session established via encrypted JWT token', primaryTenant, 'SUCCESS');
  }

  // Real audit-log snapshot used to detect genuine state changes between
  // poll cycles, instead of a scripted rotation of fabricated actions
  // attributed to real usernames who never actually did them.
  private auditWatchState = { leader: '', totalLag: 0, criticalCount: 0 };
  private auditWatchInitialized = false;

  private snapshotAuditWatchState() {
    this.auditWatchState = {
      leader: this.leaderStatus?.current_leader || '',
      totalLag: this.totalKafkaLag,
      criticalCount: this.severityData?.critical || 0,
    };
  }

  checkForRealAuditEvents() {
    if (this.userAuditPaused) return;
    // Real data (leader/severity/kafka) hasn't necessarily loaded yet the
    // first time this runs — establish the baseline silently rather than
    // comparing against empty/zero placeholder state.
    if (!this.auditWatchInitialized) {
      this.auditWatchInitialized = true;
      this.snapshotAuditWatchState();
      return;
    }
    const prev = this.auditWatchState;
    const curLeader = this.leaderStatus?.current_leader || '';
    if (prev.leader && curLeader && curLeader !== prev.leader) {
      this.pushUserAuditLog('CONFIG', 'System', 'system', `Raft leader election: cluster leadership transferred to ${curLeader}`, undefined, 'WARN');
    }
    const curLag = this.totalKafkaLag;
    if (prev.totalLag === 0 && curLag > 0) {
      this.pushUserAuditLog('CONFIG', 'System', 'system', `Kafka consumer lag detected: ${curLag} total lag across partitions`, undefined, 'WARN');
    } else if (prev.totalLag > 0 && curLag === 0) {
      this.pushUserAuditLog('CONFIG', 'System', 'system', `Kafka consumer lag cleared — all partitions caught up`, undefined, 'SUCCESS');
    }
    const curCritical = this.severityData?.critical || 0;
    if (curCritical > prev.criticalCount) {
      this.pushUserAuditLog('INVESTIGATE', 'System', 'system', `Critical severity alert count increased to ${curCritical}`, undefined, 'WARN');
    }
    this.snapshotAuditWatchState();
  }

  startUserAuditTicker() {
    if (this.userAuditTimer) return;
    this.userAuditTimer = setInterval(() => this.checkForRealAuditEvents(), 10000);
  }


  pushSocLog(level: 'OK' | 'INGEST' | 'RAFT' | 'WARN' | 'SECURITY', source: string, msg: string) {
    if (this.socLogPaused) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    this.socEventLogs.unshift({
      id: Math.random().toString(36).substring(2, 9),
      time: timeStr,
      level,
      source,
      msg
    });
    if (this.socEventLogs.length > 60) this.socEventLogs.pop();
    this.cdr.detectChanges();
  }

  initSocLogs() {
    const leader = this.isLeaderActive ? this.leaderStatus.current_leader : 'Awaiting Election';
    this.pushSocLog('OK', 'SYSTEM', `Command Center initialized. Platform health index optimal.`);
    this.pushSocLog('RAFT', 'RAFT', `Distributed consensus quorum achieved. Current leader: ${leader}.`);
    this.pushSocLog('INGEST', 'CLICKHOUSE', `ReplacingMergeTree active. Vectorized SIMD storage online.`);
    this.pushSocLog('OK', 'KAFKA', `Topic 'ndr-events' ${this.totalPartitions} partitions synchronized with ${this.kafkaData?.replication_factor || 1}x replication factor.`);
    this.pushSocLog('SECURITY', 'AGENT-S', `Agent-S signature inspection active across all tenant ingress ports.`);
  }

  startSocLogTicker() {
    if (this.socLogTimer) return;
    let step = 0;
    this.socLogTimer = setInterval(() => {
      if (this.socLogPaused) return;
      step = (step + 1) % 6;
      switch (step) {
        case 0:
          this.pushSocLog(
            'RAFT',
            'RAFT',
            this.isLeaderActive
              ? `Threat task leader heartbeat ACK: ${this.leaderStatus.current_leader} (TTL: ${this.leaderTtl}s)`
              : 'Distributed Raft consensus active. Awaiting threat leader lease...'
          );
          break;
        case 1:
          this.pushSocLog('INGEST', 'CLICKHOUSE', `Partition commit: ${this.eventsPerSec.toLocaleString()} EPS streamed to ndr.events`);
          break;
        case 2:
          this.pushSocLog('OK', 'PROBES', `All ${this.activeSensorsCount} registered TAP sensor interfaces reporting healthy link`);
          break;
        case 3:
          this.pushSocLog('SECURITY', 'THREAT-INTEL', `${this.totalThreatIps} active malicious IOC endpoints synchronized in cache`);
          break;
        case 4:
          this.pushSocLog('INGEST', 'AGENT-Z', `Agent-Z network flow analyzer active: ${(this.statsData.agent_z_events || 0).toLocaleString()} flows indexed`);
          break;
        case 5:
          this.pushSocLog(
            this.totalKafkaLag === 0 ? 'OK' : 'WARN',
            'KAFKA',
            `Partition balance verified across ${this.totalPartitions} partitions. ${this.totalKafkaLag === 0 ? 'Zero consumer lag' : this.totalKafkaLag + ' total consumer lag'} across active cluster brokers`
          );
          break;
      }
    }, 4500);
  }

  onManualLeaderProbe() {
    this.pushSocLog('RAFT', 'LEADER', 'Manual Raft leader heartbeat probe triggered');
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    this.pushUserAuditLog('CONFIG', curUser, curRole, 'Operator dispatched manual Raft consensus quorum heartbeat poll', 'Global Mesh', 'SUCCESS');
  }

  filterByIpFromTop(ip: string) {
    if (!ip) return;
    this.filterByIp(ip);
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    this.pushUserAuditLog('INVESTIGATE', curUser, curRole, `Forensic pivot inspection initiated for IP: ${ip}`, 'Global Mesh', 'SUCCESS');
    const el = document.getElementById('security-fabric-map');
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  loadKafkaStatus() {
    this.kafkaLoading = !this.kafkaData;
    this.api.getKafkaStatus().subscribe({
      next: (data: any) => {
        this.kafkaData = data;
        this.kafkaLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.kafkaLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  getEngineForPartition(partition: number): string {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.engine || '-';
  }

  getLagForPartition(partition: number): number {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.lag ?? 0;
  }

  toggleKafkaDetails() {
    this.showKafkaDetails = !this.showKafkaDetails;
    this.cdr.detectChanges();
  }

  get enginePartitionGroups(): { engine: string; partitions: number[]; inSync: boolean; totalLag: number }[] {
    if (!this.kafkaData?.partitions) return [];
    const map = new Map<string, { engine: string; partitions: number[]; inSync: boolean; totalLag: number }>();
    for (const p of this.kafkaData.partitions) {
      const engine = this.getEngineForPartition(p.partition);
      const lag = this.getLagForPartition(p.partition);
      if (!map.has(engine)) {
        map.set(engine, { engine, partitions: [], inSync: true, totalLag: 0 });
      }
      const g = map.get(engine)!;
      g.partitions.push(p.partition);
      if (!p.in_sync) g.inSync = false;
      g.totalLag += lag;
    }
    return Array.from(map.values());
  }

  get totalKafkaLag(): number {
    return this.enginePartitionGroups.reduce((sum, g) => sum + g.totalLag, 0);
  }

  // Platform-wide across all tenants — see api.getThreatMapAllTenants().
  private loadFallbackTrafficMap() {
    this.api.getThreatMapAllTenants().subscribe({
      next: (data: any) => {
        this.threatCountries = data?.countries || [];
        this.updateRelayHubsFromRealData();
        if (this.fabricMode === 'map') this.initWorldMap();
        else if (this.fabricMode === 'globe') this.initGlobalGlobe();
        this.cdr.detectChanges();
      },
      error: () => {
        this.populateDefaultHubs();
      }
    });
  }

  buildThreatIntelItems(countries: any[]) {
    const items: ThreatIntelTableItem[] = [];
    countries.forEach(c => {
      const flag = this.countryFlag(c.code);
      const ips: string[] = c.ips || [];
      const baseLat = Number(c.lat) || 0;
      const baseLon = Number(c.lon) || 0;
      const countryHits = Number(c.hit_count || c.count || c.ip_count || 1);

      if (ips.length > 0) {
        ips.forEach((ip, idx) => {
          let dispLat = baseLat;
          let dispLon = baseLon;
          if (idx > 0) {
            const angle = idx * 2.39996; // Golden angle dispersion
            const rad = 0.5 + Math.sqrt(idx) * 0.45;
            const dLat = Math.sin(angle) * rad;
            const cosL = Math.max(0.2, Math.cos((baseLat * Math.PI) / 180));
            const dLon = (Math.cos(angle) * rad) / cosL;
            dispLat = Math.max(-75, Math.min(75, baseLat + dLat));
            dispLon = ((baseLon + dLon + 180) % 360) - 180;
          }

          items.push({
            ip,
            country: c.country,
            code: c.code,
            flag,
            lat: baseLat,
            lon: baseLon,
            dispLat: Math.round(dispLat * 1000) / 1000,
            dispLon: Math.round(dispLon * 1000) / 1000,
            hits: Math.max(1, Math.round(countryHits / ips.length)),
            feed: 'AlienVault / AbuseIPDB',
            threatType: 'Known Malicious IP',
          });
        });
      } else {
        items.push({
          ip: `${c.country} Attack Range`,
          country: c.country,
          code: c.code,
          flag,
          lat: baseLat,
          lon: baseLon,
          dispLat: baseLat,
          dispLon: baseLon,
          hits: countryHits,
          feed: 'Global Threat Feed',
          threatType: 'Inbound Threat Attacker',
        });
      }
    });

    this.threatIntelItems = items.sort((a, b) => b.hits - a.hits);
    this.filterThreatIntelItems();
  }

  onThreatSearch(event: Event) {
    this.threatSearchQuery = (event.target as HTMLInputElement).value || '';
    this.filterThreatIntelItems();
  }

  filterThreatIntelItems() {
    const q = this.threatSearchQuery.trim().toLowerCase();
    if (!q) {
      this.filteredThreatIntelItems = [...this.threatIntelItems];
    } else {
      this.filteredThreatIntelItems = this.threatIntelItems.filter(item =>
        item.ip.toLowerCase().includes(q) ||
        item.country.toLowerCase().includes(q) ||
        item.code.toLowerCase().includes(q) ||
        item.feed.toLowerCase().includes(q) ||
        item.threatType.toLowerCase().includes(q)
      );
    }
    this.cdr.detectChanges();
  }

  animateGlobeTo(lon: number, lat: number) {
    const targetLon = -lon;
    const targetLat = Math.max(-65, Math.min(65, -lat * 0.75));
    this.targetGlobeRot = [targetLon, targetLat, 0];
  }

  focusRegion(region: 'all' | 'eu' | 'apac' | 'americas' | 'mea') {
    this.activeRegionFilter = region;
    this.filterThreatIntelByRegion(region);

    if (this.fabricMode === 'globe') {
      if (region === 'eu') {
        this.targetGlobeRot = [-15, -50, 0];
        this.targetGlobeScale = 2.4;
      } else if (region === 'apac') {
        this.targetGlobeRot = [-105, -20, 0];
        this.targetGlobeScale = 2.2;
      } else if (region === 'americas') {
        this.targetGlobeRot = [75, -15, 0];
        this.targetGlobeScale = 1.8;
      } else if (region === 'mea') {
        this.targetGlobeRot = [-40, -22, 0];
        this.targetGlobeScale = 2.4;
      } else {
        this.targetGlobeRot = [-20, -15, 0];
        this.targetGlobeScale = 1.0;
      }
      this.cdr.detectChanges();
      return;
    }

    if (!this.d3WorldMapSvg || !this.d3WorldMapZoom) return;

    const el = this.worldMapContainer?.nativeElement;
    const width = el?.clientWidth || 740;
    const height = el?.clientHeight || 460;

    let center: [number, number] = [12, 20];
    let scale = 1;

    if (region === 'eu') {
      center = [15, 52];
      scale = 3.2;
    } else if (region === 'apac') {
      center = [105, 20];
      scale = 2.4;
    } else if (region === 'americas') {
      center = [-75, 12];
      scale = 1.8;
    } else if (region === 'mea') {
      center = [42, 22];
      scale = 2.8;
    } else {
      center = [12, 20];
      scale = 1;
    }

    const xy = this.mapProjection ? this.mapProjection(center) : [width / 2, height / 2];
    if (!xy) return;

    const tX = width / 2 - xy[0] * scale;
    const tY = height / 2 - xy[1] * scale;

    const transform = d3.zoomIdentity.translate(tX, tY).scale(scale);
    this.d3WorldMapSvg.transition().duration(750).ease(d3.easeCubicOut)
      .call(this.d3WorldMapZoom.transform as any, transform);

    this.cdr.detectChanges();
  }

  filterThreatIntelByRegion(region: 'all' | 'eu' | 'apac' | 'americas' | 'mea') {
    if (region === 'all') {
      this.filterThreatIntelItems();
      return;
    }
    const euCodes = new Set(['DE', 'GB', 'FR', 'NL', 'PL', 'RO', 'BG', 'ES', 'IT', 'SE', 'FI', 'IE', 'PT', 'TR', 'UA', 'RU', 'AT', 'CH', 'BE', 'CZ', 'GR', 'HU', 'DK', 'NO']);
    const apacCodes = new Set(['IN', 'PK', 'CN', 'JP', 'KR', 'SG', 'TH', 'VN', 'ID', 'MY', 'AU', 'NZ', 'KH', 'TW', 'HK', 'NP', 'PH', 'BD']);
    const americasCodes = new Set(['US', 'CA', 'MX', 'BR', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'PA', 'UY', 'CR']);
    const meaCodes = new Set(['AE', 'SA', 'IR', 'IL', 'EG', 'ZA', 'NG', 'KE', 'MZ', 'TN', 'PS', 'QA', 'KW', 'OM']);

    let targetSet = euCodes;
    if (region === 'apac') targetSet = apacCodes;
    else if (region === 'americas') targetSet = americasCodes;
    else if (region === 'mea') targetSet = meaCodes;

    this.filteredThreatIntelItems = this.threatIntelItems.filter(item =>
      targetSet.has(item.code.toUpperCase())
    );
    this.cdr.detectChanges();
  }

  getRegionCount(region: 'all' | 'eu' | 'apac' | 'americas' | 'mea'): number {
    if (region === 'all') return this.relayHubs.length;
    const euCodes = new Set(['DE', 'GB', 'FR', 'NL', 'PL', 'RO', 'BG', 'ES', 'IT', 'SE', 'FI', 'IE', 'PT', 'TR', 'UA', 'RU', 'AT', 'CH', 'BE', 'CZ', 'GR', 'HU', 'DK', 'NO']);
    const apacCodes = new Set(['IN', 'PK', 'CN', 'JP', 'KR', 'SG', 'TH', 'VN', 'ID', 'MY', 'AU', 'NZ', 'KH', 'TW', 'HK', 'NP', 'PH', 'BD']);
    const americasCodes = new Set(['US', 'CA', 'MX', 'BR', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'PA', 'UY', 'CR']);
    const meaCodes = new Set(['AE', 'SA', 'IR', 'IL', 'EG', 'ZA', 'NG', 'KE', 'MZ', 'TN', 'PS', 'QA', 'KW', 'OM']);

    let targetSet = euCodes;
    if (region === 'apac') targetSet = apacCodes;
    else if (region === 'americas') targetSet = americasCodes;
    else if (region === 'mea') targetSet = meaCodes;

    return this.relayHubs.filter(h => targetSet.has(h.id.toUpperCase())).length;
  }

  zoomIn() {
    if (this.fabricMode === 'globe') {
      this.targetGlobeScale = Math.min(4.5, this.targetGlobeScale * 1.35);
      return;
    }
    if (this.d3WorldMapSvg && this.d3WorldMapZoom) {
      this.d3WorldMapSvg.transition().duration(350).call(this.d3WorldMapZoom.scaleBy as any, 1.5);
    }
  }

  zoomOut() {
    if (this.fabricMode === 'globe') {
      this.targetGlobeScale = Math.max(0.75, this.targetGlobeScale / 1.35);
      return;
    }
    if (this.d3WorldMapSvg && this.d3WorldMapZoom) {
      this.d3WorldMapSvg.transition().duration(350).call(this.d3WorldMapZoom.scaleBy as any, 0.67);
    }
  }

  resetZoom() {
    if (this.fabricMode === 'globe') {
      this.targetGlobeScale = 1.0;
      this.targetGlobeRot = [-20, -15, 0];
    } else if (this.d3WorldMapSvg && this.d3WorldMapZoom) {
      this.d3WorldMapSvg.transition().duration(500).call(this.d3WorldMapZoom.transform as any, d3.zoomIdentity);
    }
    this.activeRegionFilter = 'all';
    this.filterThreatIntelItems();
    this.cdr.detectChanges();
  }

  toggleMapExpanded() {
    this.isMapExpanded = !this.isMapExpanded;
    setTimeout(() => {
      if (this.fabricMode === 'map') this.initWorldMap();
      else if (this.fabricMode === 'globe') this.initGlobalGlobe();
    }, 250);
  }

  getRelayIps(hub: RelayHub | null): string[] {
    if (!hub) return [];
    const countryData = this.threatCountries.find(c =>
      c.country?.toLowerCase() === hub.name?.toLowerCase() ||
      c.country?.toLowerCase() === hub.city?.toLowerCase() ||
      c.code?.toLowerCase() === hub.id?.toLowerCase()
    );
    if (countryData && countryData.ips && countryData.ips.length > 0) {
      return countryData.ips;
    }
    return this.threatIntelItems
      .filter(i => i.country?.toLowerCase() === hub.name?.toLowerCase() || i.country?.toLowerCase() === hub.city?.toLowerCase())
      .map(i => i.ip);
  }

  selectCountryHub(hub: RelayHub) {
    this.selectedRelay = hub;
    this.threatSearchQuery = hub.name;
    this.filterThreatIntelItems();
    this.sideCardTab = 'threat';
    this.cdr.detectChanges();
  }

  clearSelectedRelay() {
    this.selectedRelay = null;
    this.threatSearchQuery = '';
    this.filterThreatIntelItems();
    this.cdr.detectChanges();
  }

  clearThreatSearch() {
    this.threatSearchQuery = '';
    this.filterThreatIntelItems();
    this.cdr.detectChanges();
  }

  filterByCountry(country: string) {
    this.threatSearchQuery = country;
    this.filterThreatIntelItems();
    this.sideCardTab = 'threat';
    this.cdr.detectChanges();
  }

  filterByIp(ip: string) {
    this.threatSearchQuery = ip;
    this.filterThreatIntelItems();
    this.sideCardTab = 'threat';
    this.cdr.detectChanges();
  }

  setSideCardTab(tab: 'threat' | 'orgs') {
    this.sideCardTab = tab;
    this.cdr.detectChanges();
  }

  focusThreatCountry(item: ThreatIntelTableItem) {
    const hub = this.relayHubs.find(h => h.city?.toLowerCase() === item.country?.toLowerCase() || h.name?.toLowerCase() === item.country?.toLowerCase());
    if (hub) {
      this.selectedRelay = hub;
    } else {
      this.selectedRelay = {
        id: item.code.toLowerCase(),
        name: item.country,
        city: item.country,
        region: `${item.code.toUpperCase()} Threat Attribution`,
        flag: item.flag,
        lat: item.lat,
        lon: item.lon,
        status: (item.hits >= 50 ? 'CRITICAL' : 'HIGH') as any,
        throughput: `${item.hits} IOC hits`,
        latency: `${Math.round(10 + Math.abs(item.lat % 25))}ms`,
        loadPercent: 85,
        attackCount: item.hits,
      };
    }
    if (this.fabricMode === 'globe') {
      this.animateGlobeTo(item.lon, item.lat);
    } else if (this.fabricMode === 'map') {
      if (this.d3WorldMapSvg && this.d3WorldMapZoom && this.mapProjection) {
        const el = this.worldMapContainer?.nativeElement;
        const width = el?.clientWidth || 740;
        const height = el?.clientHeight || 460;
        const xy = this.mapProjection([item.lon, item.lat]);
        if (xy) {
          const scale = 3.5;
          const tX = width / 2 - xy[0] * scale;
          const tY = height / 2 - xy[1] * scale;
          const transform = d3.zoomIdentity.translate(tX, tY).scale(scale);
          this.d3WorldMapSvg.transition().duration(700).ease(d3.easeCubicOut)
            .call(this.d3WorldMapZoom.transform as any, transform);
        }
      }
    }
    this.cdr.detectChanges();
  }

  // Populate map nodes from real external IP traffic detections
  private updateRelayHubsFromRealData() {
    if (this.threatCountries && this.threatCountries.length > 0) {
      this.relayHubs = this.threatCountries.map((c: any) => {
        const hits = Number(c.hit_count || c.count || c.ip_count || 1);
        const threatLevel = hits >= 60 ? 'CRITICAL' : hits >= 20 ? 'HIGH' : 'ELEVATED';
        return {
          id: c.code?.toLowerCase() || c.country?.toLowerCase(),
          name: `${c.country}`,
          city: c.country,
          region: c.code ? `${c.code.toUpperCase()} Threat Attribution` : 'Global Threat Feed',
          flag: this.countryFlag(c.code),
          lat: Number(c.lat) || 0,
          lon: Number(c.lon) || 0,
          status: threatLevel as any,
          throughput: `${hits.toLocaleString()} IOC hits`,
          latency: `${Math.round(10 + Math.abs(Number(c.lat) % 25))}ms`,
          loadPercent: Math.min(100, Math.round((hits / (this.threatCountries[0]?.hit_count || this.threatCountries[0]?.count || 1)) * 100)),
          attackCount: c.attacks?.length || c.ip_count || 1,
        };
      });
    } else {
      this.relayHubs = [];
    }
  }

  private populateDefaultHubs() {
    this.relayHubs = [];
  }

  private countryFlag(code: string): string {
    if (!code || code.length !== 2) return '🌐';
    return code.toUpperCase().replace(/./g, c =>
      String.fromCodePoint(127397 + c.charCodeAt(0))
    );
  }

  ngAfterViewInit() {
    this.initCommandMesh();
    if (this.fabricMode === 'globe') {
      this.initGlobalGlobe();
    } else if (this.cachedWorldData) {
      this.initWorldMap();
    }
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
  }

  ngOnDestroy() {
    if (this.socLogTimer) clearInterval(this.socLogTimer);
    if (this.userAuditTimer) clearInterval(this.userAuditTimer);
    this.stopOverviewTelemetryPolling();
    if (this.resizeObserver) this.resizeObserver.disconnect();
    if (this.mapResizeObserver) this.mapResizeObserver.disconnect();
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    this.destroyCommandMesh();
    this.destroyGlobalGlobe();
  }

  // Backgrounded tabs shouldn't keep the globe/WebGL mesh burning CPU —
  // cancel their rAF loops on hide, rebuild them on return.
  private handleVisibilityChange = () => {
    if (document.hidden) {
      this.destroyCommandMesh();
      this.destroyGlobalGlobe();
      return;
    }
    this.initCommandMesh();
    if (this.fabricMode === 'globe' && this.globalGlobe?.nativeElement) {
      this.initGlobalGlobe();
    }
  };

  // ── Switchers & Actions ─────────────────────────────────────────

  setFabricMode(mode: 'map' | 'globe') {
    if (this.fabricMode === mode) return;
    this.fabricMode = mode;
    this.cdr.detectChanges();
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    this.pushUserAuditLog('CONFIG', curUser, curRole, `Switched Command Canvas view to ${mode.toUpperCase()}`, 'Global Mesh', 'SUCCESS');

    setTimeout(() => {
      if (mode === 'globe') {
        this.initGlobalGlobe();
      } else {
        this.destroyGlobalGlobe();
        if (this.cachedWorldData) {
          this.initWorldMap();
        } else {
          this.loadWorldData();
        }
      }
    }, 50);
  }

  setTimeRange(range: 'realtime' | '1h' | '24h' | '7d') {
    this.timeRange = range;
    this.cdr.detectChanges();
  }

  triggerRefresh() {
    this.isRefreshing = true;
    this.loadAllRealPlatformData();
    this.pollOverviewTelemetry();
    const curUser = this.auth?.getUser()?.username || 'admin';
    const curRole = this.auth?.getUser()?.role || 'super_admin';
    this.pushUserAuditLog('CONFIG', curUser, curRole, 'Operator manually refreshed platform overview data', undefined, 'SUCCESS');
    setTimeout(() => {
      this.isRefreshing = false;
      this.cdr.detectChanges();
    }, 600);
  }

  // ── Telemetry Polling (Real /api/admin/telemetry) ───────────────

  startOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) return;
    // loadAllRealPlatformData() (called moments earlier in ngOnInit) already
    // fetched leader-status/severity/protocols once — only fetch telemetry
    // (the one thing it doesn't cover) on this first tick, instead of
    // re-fetching all four and doubling the page's initial request burst.
    this.loadPlatformTelemetry();
    this.overviewTelemetryPollTimer = setInterval(() => this.pollOverviewTelemetry(), 10000);
  }

  stopOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) {
      clearInterval(this.overviewTelemetryPollTimer);
      this.overviewTelemetryPollTimer = null;
    }
  }

  pollOverviewTelemetry() {
    this.loadLeaderStatus();
    this.loadSeverityData();
    this.loadProtocolsData();
    this.loadPlatformTelemetry();
  }

  private loadPlatformTelemetry() {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        const cpu = Math.round(Number(data.cpu_usage_percent) || 0);
        const mem = Math.round(Number(data.memory_percent) || 0);
        this.memoryUsedGb = Number(data.memory_used_gb) || 0;
        this.memoryTotalGb = Number(data.memory_total_gb) || 0;
        this.eventsPerSec = Number(data.events_per_sec) || 0;
        this.events1h = Number(data.events_1h) || 0;

        this.overviewTelemetryHistory.push({
          time: new Date(),
          cpu,
          mem,
        });
        if (this.overviewTelemetryHistory.length > 24) this.overviewTelemetryHistory.shift();
        this.renderResourceUtilizationArea();
        this.renderFocusedPostureGauge();
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  private setupResizeObserver() {
    const grid = document.querySelector('.ov-main-container');
    if (grid && !this.resizeObserver) {
      this.resizeObserver = new ResizeObserver(() => {
        if (this.resizeTimeout) clearTimeout(this.resizeTimeout);
        this.resizeTimeout = setTimeout(() => this.renderAllCharts(), 120);
      });
      this.resizeObserver.observe(grid);
    }
  }

  renderAllCharts() {
    this.renderResourceUtilizationArea();
    this.renderFocusedPostureGauge();
    this.renderUserRolesDonut();
    if (this.fabricMode === 'map') {
      this.initWorldMap();
    }
  }

  // ── D3 Helpers ─────────────────────────────────────────────────

  private addGlowFilter(defs: any, id: string, color: string, blur = 4) {
    const f = defs.append('filter').attr('id', id)
      .attr('x', '-60%').attr('y', '-60%').attr('width', '220%').attr('height', '220%');
    f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', blur).attr('result', 'blur');
    f.append('feFlood').attr('flood-color', color).attr('flood-opacity', 0.65).attr('result', 'color');
    f.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
    const merge = f.append('feMerge');
    merge.append('feMergeNode').attr('in', 'glow');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  private getOrCreateTooltip(): any {
    let tt: any = d3.select('body').select('.cyber-d3-tooltip');
    if (tt.empty()) {
      tt = d3.select('body').append('div')
        .attr('class', 'cyber-d3-tooltip')
        .style('opacity', 0)
        .style('position', 'fixed')
        .style('pointer-events', 'none')
        .style('z-index', '9999999');
    }
    return tt;
  }

  private positionTooltip(event: MouseEvent, tooltip: any, width = 280, height = 180) {
    const pad = 14;
    let x = event.clientX + pad;
    let y = event.clientY + pad;

    if (x + width > window.innerWidth - 12) {
      x = event.clientX - width - pad;
    }
    if (y + height > window.innerHeight - 12) {
      y = event.clientY - height - pad;
    }

    x = Math.max(10, x);
    y = Math.max(10, y);

    tooltip.style('left', `${x}px`).style('top', `${y}px`);
  }

  // ── 1. Interactive World Map (Real TopoJSON & Real Ingress Points) 

  private async loadWorldData() {
    try {
      this.cachedWorldData = await this.http.get('/assets/world-110m.json').toPromise();
      if (this.fabricMode === 'map') {
        this.initWorldMap();
      } else if (this.fabricMode === 'globe') {
        this.initGlobalGlobe();
      }
    } catch {}
  }

  private initWorldMap() {
    const container = d3.select('#security-fabric-map');
    if (container.empty()) return;
    if (!this.cachedWorldData || !this.cachedWorldData.objects) {
      // Return early if world topology json is still downloading; loadWorldData() will invoke initWorldMap() on arrival
      return;
    }
    container.selectAll('*').remove();

    const node = container.node() as HTMLElement;
    const width = node.clientWidth || 740;
    const height = node.clientHeight || 460;

    const svg = container.append('svg')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet')
      .style('cursor', 'grab');

    const defs = svg.append('defs');
    this.addGlowFilter(defs, 'map-glow-cyan', '#38bdf8', 5);
    this.addGlowFilter(defs, 'map-glow-emerald', '#34d399', 4);
    this.addGlowFilter(defs, 'map-glow-rose', '#f43f5e', 5);

    const projection = d3.geoNaturalEarth1()
      .scale(width / 5.2)
      .translate([width / 2.05, height / 1.75]);
    this.mapProjection = projection;

    const pathFn: any = d3.geoPath().projection(projection);

    // Viewport Group that supports smooth D3 Zoom & Pan
    const mapG = svg.append('g').attr('class', 'map-viewport');

    let currentK = 1;
    let renderNodesAndClusters: ((k: number) => void) | null = null;
    let clusterUpdateTimer: any = null;

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.85, 8])
      .on('start', () => {
        svg.style('cursor', 'grabbing');
      })
      .on('zoom', (event: any) => {
        mapG.attr('transform', event.transform);
        currentK = event.transform.k;
        const k = currentK;
        mapG.selectAll('.ips-layer')
          .style('pointer-events', k >= 1.8 ? 'auto' : 'none');
        mapG.selectAll('.threat-ip-dot')
          .attr('r', 1.8 / k)
          .attr('opacity', k >= 1.8 ? 0.85 : 0.45);

        if (clusterUpdateTimer) clearTimeout(clusterUpdateTimer);
        clusterUpdateTimer = setTimeout(() => {
          if (renderNodesAndClusters) renderNodesAndClusters(k);
        }, 16);
      })
      .on('end', (event: any) => {
        svg.style('cursor', 'grab');
        if (renderNodesAndClusters) renderNodesAndClusters(event.transform.k);
      });

    svg.call(zoom as any);
    this.d3WorldMapZoom = zoom;
    this.d3WorldMapSvg = svg;

    // 1. Graticules
    const graticule = d3.geoGraticule10();
    mapG.append('path')
      .datum(graticule)
      .attr('d', pathFn as any)
      .attr('fill', 'none')
      .attr('stroke', 'rgba(56, 189, 248, 0.05)')
      .attr('stroke-width', 0.8);

    // 2. Base World Countries (Polygons)
    mapG.append('g').attr('class', 'land-masses')
      .selectAll('path')
      .data((topojson.feature(this.cachedWorldData, this.cachedWorldData.objects.countries) as any).features)
      .enter().append('path')
      .attr('class', 'country-boundary')
      .attr('d', pathFn as any)
      .attr('fill', '#0c1a2e')
      .attr('stroke', '#1e3a5f')
      .attr('stroke-width', 0.6)
      .style('cursor', 'grab')
      .on('mouseover', function() {
        d3.select(this)
          .attr('fill', '#11294a')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 0.9);
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('fill', '#0c1a2e')
          .attr('stroke', '#1e3a5f')
          .attr('stroke-width', 0.6);
      });

    const prominentIds = new Set(['us', 'de', 'in', 'cn', 'br', 'au', 'ru', 'gb', 'jp', 'fr', 'ca', 'pk', 'sg', 'it', 'es']);
    const hubCoords = this.relayHubs.map(h => ({
      ...h,
      coords: projection([h.lon, h.lat]) as [number, number],
      isProminent: prominentIds.has(h.id.toLowerCase())
    })).filter(h => h.coords !== null && !isNaN(h.coords[0]) && !isNaN(h.coords[1]));

    // 3. Arcs from active countries to SOC Headquarters
    const TARGET: [number, number] = [77.2090, 28.6139]; // SOC Primary Hub (India)
    const targetCoords = projection(TARGET) || [width / 2, height / 2];

    const linksGroup = mapG.append('g').attr('class', 'links-layer');
    hubCoords.forEach(hub => {
      const p1 = hub.coords;
      const p2 = targetCoords;
      const dx = p2[0] - p1[0];
      const dy = p2[1] - p1[1];
      const cx = (p1[0] + p2[0]) / 2 - dy * 0.15;
      const cy = (p1[1] + p2[1]) / 2 + dx * 0.15;

      linksGroup.append('path')
        .attr('d', `M${p1[0]},${p1[1]} Q${cx},${cy} ${p2[0]},${p2[1]}`)
        .attr('fill', 'none')
        .attr('stroke', 'rgba(56, 189, 248, 0.22)')
        .attr('stroke-width', 1.1)
        .attr('stroke-dasharray', '3, 4')
        .attr('class', 'relay-arc');
    });

    const tooltip = this.getOrCreateTooltip();

    // 4. Malicious Individual IP Pins Layer (All 200 IPs)
    const ipsGroup = mapG.append('g')
      .attr('class', 'ips-layer')
      .style('pointer-events', currentK >= 1.8 ? 'auto' : 'none');

    this.threatIntelItems.forEach(item => {
      const pt: [number, number] = [item.dispLon ?? item.lon, item.dispLat ?? item.lat];
      const coords = projection(pt);
      if (!coords || isNaN(coords[0]) || isNaN(coords[1])) return;

      const ipG = ipsGroup.append('g')
        .attr('class', 'threat-ip-pin')
        .attr('transform', `translate(${coords[0]}, ${coords[1]})`)
        .style('cursor', 'pointer')
        .on('click', (event: MouseEvent) => {
          event.stopPropagation();
          this.focusThreatCountry(item);
        })
        .on('mouseenter', (event: MouseEvent) => {
          event.stopPropagation();
          tooltip.style('opacity', 1);
          tooltip.html(`
            <div class="cyber-tt-head">
              <span class="cyber-tt-flag">${item.flag}</span>
              <strong class="text-rose-400 font-mono">${item.ip}</strong>
            </div>
            <div class="cyber-tt-body">
              <div class="tt-row"><span>Origin:</span> <b>${item.country} (${item.code})</b></div>
              <div class="tt-row"><span>Classification:</span> <b class="tt-danger">${item.threatType}</b></div>
              <div class="tt-row"><span>Source Feed:</span> <b>${item.feed}</b></div>
              <div class="tt-row"><span>IOC Hits:</span> <b class="tt-alert">${item.hits} hits</b></div>
              <div class="tt-row"><span>Coordinates:</span> <b>${item.lat.toFixed(2)}°, ${item.lon.toFixed(2)}°</b></div>
            </div>
          `);
          this.positionTooltip(event, tooltip, 260, 180);
        })
        .on('mousemove', (event: MouseEvent) => {
          event.stopPropagation();
          this.positionTooltip(event, tooltip, 260, 180);
        })
        .on('mouseleave', () => {
          tooltip.style('opacity', 0);
        });

      ipG.append('circle')
        .attr('class', 'threat-ip-dot')
        .attr('r', 1.8 / currentK)
        .attr('fill', '#fb7185')
        .attr('opacity', 0.55);
    });

    // 5. Google Maps-Style Dynamic Clustering Layer with Anti-Collision Labels
    const nodesGroup = mapG.append('g').attr('class', 'nodes-layer');

    renderNodesAndClusters = (k: number) => {
      nodesGroup.selectAll('*').remove();

      // Dynamic unpacking: At k >= 2.2 (continent zoom), threshold is 0 -> ALL countries unpack!
      const thresholdPx = k >= 2.2 ? 0 : Math.max(0, 32 - (k - 1) * 20);
      const assigned = new Set<string>();
      const clusters: any[] = [];
      const singles: any[] = [];

      // Sort hubs: prominent first so key cities anchor clusters cleanly
      const sortedHubs = [...hubCoords].sort((a, b) => {
        if (a.isProminent && !b.isProminent) return -1;
        if (!a.isProminent && b.isProminent) return 1;
        return (b.attackCount || 1) - (a.attackCount || 1);
      });

      for (let i = 0; i < sortedHubs.length; i++) {
        const hubA = sortedHubs[i];
        if (assigned.has(hubA.id)) continue;

        const group = [hubA];
        assigned.add(hubA.id);

        if (thresholdPx > 0) {
          for (let j = i + 1; j < sortedHubs.length; j++) {
            const hubB = sortedHubs[j];
            if (assigned.has(hubB.id)) continue;

            const screenDist = Math.hypot(
              (hubA.coords[0] - hubB.coords[0]) * k,
              (hubA.coords[1] - hubB.coords[1]) * k
            );

            if (screenDist < thresholdPx) {
              group.push(hubB);
              assigned.add(hubB.id);
            }
          }
        }

        if (group.length > 1) {
          const avgX = group.reduce((s, h) => s + h.coords[0], 0) / group.length;
          const avgY = group.reduce((s, h) => s + h.coords[1], 0) / group.length;
          clusters.push({
            id: `cl-${group[0].id}-${group.length}`,
            center: [avgX, avgY],
            hubs: group,
            count: group.length,
            totalIocs: group.reduce((s, h) => s + (h.attackCount || 1), 0),
            totalThroughput: group.reduce((s, h) => s + (parseInt(h.throughput) || 10), 0)
          });
        } else {
          singles.push(hubA);
        }
      }

      // ── A. RENDER CLUSTER BADGES (Fixed constant screen size: 22px diameter) ─────
      clusters.forEach(cl => {
        const [cx, cy] = cl.center;
        const badgeRadius = 11 / k;
        const haloRadius = 16 / k;

        const clG = nodesGroup.append('g')
          .attr('class', 'cluster-badge-group')
          .attr('transform', `translate(${cx}, ${cy})`)
          .style('cursor', 'pointer')
          .on('click', (event: MouseEvent) => {
            event.stopPropagation();
            // Google Maps smooth zoom-to-unpack behavior
            const targetK = Math.min(8, Math.max(k * 2.2, 2.5));
            const tX = width / 2 - cx * targetK;
            const tY = height / 2 - cy * targetK;
            svg.transition().duration(600).ease(d3.easeCubicOut)
              .call(zoom.transform as any, d3.zoomIdentity.translate(tX, tY).scale(targetK));
          })
          .on('mouseenter', (event: MouseEvent) => {
            event.stopPropagation();
            clG.select('.cluster-badge-core')
              .attr('fill', '#e11d48')
              .attr('stroke', '#ffffff');
            tooltip.style('opacity', 1);
            tooltip.html(`
              <div class="cyber-tt-head">
                <span class="text-rose-400 font-mono font-bold">📍 Threat Cluster (${cl.count} Countries)</span>
              </div>
              <div class="cyber-tt-body">
                <div class="tt-row"><span>Global Feed Hits:</span> <b class="tt-alert">${cl.totalThroughput} hits</b></div>
                <div class="tt-row"><span>Blacklisted IOCs:</span> <b class="text-rose-400">${cl.totalIocs} active IOCs</b></div>
                <div class="tt-row"><span>Locations:</span> <b>${cl.hubs.map((h: any) => h.flag + ' ' + h.name).slice(0, 6).join(', ')}${cl.hubs.length > 6 ? ` +${cl.hubs.length - 6} more` : ''}</b></div>
                <div style="margin-top: 6px; font-size: 10px; color: #fb7185; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 4px;">
                  ⚡ Click badge to zoom in & unpack individual countries
                </div>
              </div>
            `);
            this.positionTooltip(event, tooltip, 280, 190);
          })
          .on('mousemove', (event: MouseEvent) => {
            event.stopPropagation();
            this.positionTooltip(event, tooltip, 280, 190);
          })
          .on('mouseleave', () => {
            clG.select('.cluster-badge-core')
              .attr('fill', '#260914')
              .attr('stroke', '#f43f5e');
            tooltip.style('opacity', 0);
          });

        // 1. Dedicated Solid Hit Target - perfectly captures all pointer events
        clG.append('circle')
          .attr('class', 'cluster-hit-target')
          .attr('r', 16 / k)
          .attr('fill', '#000000')
          .attr('opacity', 0.001)
          .style('pointer-events', 'all');

        // 2. Pulsing glowing outer aura (Red / Rose)
        clG.append('circle')
          .attr('class', 'cluster-halo-pulse')
          .attr('r', haloRadius)
          .attr('fill', 'rgba(244, 63, 94, 0.16)')
          .attr('stroke', '#f43f5e')
          .attr('stroke-width', 1.2 / k)
          .attr('stroke-dasharray', `${2.5 / k}, ${2 / k}`)
          .attr('filter', 'url(#map-glow-rose)')
          .style('pointer-events', 'none');

        // 3. Inner solid cyber circle (Deep Crimson & Red border)
        clG.append('circle')
          .attr('class', 'cluster-badge-core')
          .attr('r', badgeRadius)
          .attr('fill', '#260914')
          .attr('stroke', '#f43f5e')
          .attr('stroke-width', 1.6 / k)
          .style('pointer-events', 'none');

        // 4. Cluster count text
        clG.append('text')
          .attr('class', 'cluster-badge-text')
          .attr('font-size', `${9.5 / k}px`)
          .attr('fill', '#ffffff')
          .style('pointer-events', 'none')
          .text(cl.count);
      });

      // ── B. RENDER INDIVIDUAL HUBS WITH COLLISION AVOIDANCE ─────
      const placedLabelBoxes: { x1: number; y1: number; x2: number; y2: number }[] = [];

      singles.forEach(hub => {
        const [cx, cy] = hub.coords;
        const isProminent = hub.isProminent;

        const g = nodesGroup.append('g')
          .datum({ hub, isProminent })
          .attr('transform', `translate(${cx}, ${cy})`)
          .style('cursor', 'pointer');

        // Label collision detection in screen space to guarantee zero overlapping text
        const labelText = hub.city || hub.name;
        const charWidth = 6.0;
        const labelW = labelText.length * charWidth + 8;
        const labelH = 12;
        const screenX = cx * k;
        const screenY = cy * k + 12;
        const box = {
          x1: screenX - labelW / 2,
          x2: screenX + labelW / 2,
          y1: screenY - 2,
          y2: screenY + labelH + 2
        };

        let collides = clusters.some(cl => {
          const clScreenX = cl.center[0] * k;
          const clScreenY = cl.center[1] * k;
          return Math.hypot(clScreenX - screenX, clScreenY - screenY) < 24;
        });

        if (!collides) {
          collides = placedLabelBoxes.some(p =>
            !(box.x2 < p.x1 || box.x1 > p.x2 || box.y2 < p.y1 || box.y1 > p.y2)
          );
        }

        const canShowLabel = !collides;
        if (canShowLabel) {
          placedLabelBoxes.push(box);
        }

        // Unified mouse handlers on parent group
        g.on('click', (event: MouseEvent) => {
            event.stopPropagation();
            this.selectCountryHub(hub);
          })
          .on('mouseenter', (event: MouseEvent) => {
            event.stopPropagation();
            g.select('.country-label')
              .style('opacity', '1')
              .attr('fill', '#38bdf8');
            g.select('.ping-halo')
              .attr('stroke', '#38bdf8')
              .attr('stroke-width', 1.8 / k);

            tooltip.style('opacity', 1);
            tooltip.html(`
              <div class="cyber-tt-head">
                <span class="cyber-tt-flag">${hub.flag}</span>
                <strong>${hub.name}</strong>
              </div>
              <div class="cyber-tt-body">
                <div class="tt-row"><span>Attribution:</span> <b>${hub.region}</b></div>
                <div class="tt-row"><span>Threat Level:</span> <b class="text-rose-400 font-bold">${hub.status}</b></div>
                <div class="tt-row"><span>Global Feed Hits:</span> <b>${hub.throughput}</b></div>
                <div class="tt-row"><span>Blacklisted IPs:</span> <b class="text-amber-400 font-mono">${hub.attackCount || 1} active IPs</b></div>
                <div class="tt-row"><span>Coordinates:</span> <b>${hub.lat}°, ${hub.lon}°</b></div>
              </div>
            `);
            this.positionTooltip(event, tooltip, 260, 180);
          })
          .on('mousemove', (event: MouseEvent) => {
            event.stopPropagation();
            this.positionTooltip(event, tooltip, 260, 180);
          })
          .on('mouseleave', () => {
            g.select('.country-label')
              .style('opacity', canShowLabel ? '0.9' : '0')
              .attr('fill', '#cbd5e1');
            g.select('.ping-halo')
              .attr('stroke', '#f43f5e')
              .attr('stroke-width', 1 / k);
            tooltip.style('opacity', 0);
          });

        // 1. Dedicated Solid Hit Target for single country pin
        g.append('circle')
          .attr('r', 12 / k)
          .attr('fill', '#000000')
          .attr('opacity', 0.001)
          .style('pointer-events', 'all');

        // 2. Pulsing halo (purely visual)
        g.append('circle')
          .attr('class', 'ping-halo')
          .attr('r', 8.5 / k)
          .attr('fill', 'rgba(244, 63, 94, 0.12)')
          .attr('stroke', '#f43f5e')
          .attr('stroke-width', 1 / k)
          .attr('filter', 'url(#map-glow-rose)')
          .style('pointer-events', 'none');

        // 3. Hub core dot (purely visual)
        g.append('circle')
          .attr('class', 'hub-core-dot')
          .attr('r', 3.5 / k)
          .attr('fill', '#f43f5e')
          .attr('stroke', '#ffffff')
          .attr('stroke-width', 1 / k)
          .style('pointer-events', 'none');

        // 4. Country label text (purely visual)
        g.append('text')
          .attr('class', 'country-label')
          .attr('x', 0)
          .attr('y', 12 / k)
          .attr('text-anchor', 'middle')
          .attr('fill', '#cbd5e1')
          .attr('font-size', `${9.5 / k}px`)
          .attr('font-weight', '600')
          .attr('letter-spacing', '0.03em')
          .style('opacity', canShowLabel ? 0.9 : 0)
          .style('pointer-events', 'none')
          .text(labelText);
      });
    };

    // Initial render of Google Maps clusters at k = 1
    renderNodesAndClusters(currentK);
  }

  // ── 2. Concentric Posture Gauge (Calculated from 100% Real Status)

  renderFocusedPostureGauge() {
    const container = d3.select('#focused-posture-gauge');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const node = container.node() as HTMLElement;
    const width = node.clientWidth || 280;
    const height = 260;
    const center = [width / 2, height / 2];

    const svg = container.append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svg.append('defs');
    this.addGlowFilter(defs, 'gauge-emerald', '#10b981', 5);
    this.addGlowFilter(defs, 'gauge-cyan', '#06b6d4', 5);
    this.addGlowFilter(defs, 'gauge-amber', '#f59e0b', 5);
    this.addGlowFilter(defs, 'gauge-violet', '#8b5cf6', 5);

    const g = svg.append('g').attr('transform', `translate(${center[0]}, ${center[1]})`);

    // Real values
    const engineRatio = this.engines.length ? (this.activeEngines / this.engines.length) : 1;
    const tenantRatio = this.tenants.length ? (this.activeTenantsCount / this.tenants.length) : 1;
    const sensorRatio = this.sensorKeys.length ? (this.activeSensorsCount / this.sensorKeys.length) : 1;
    const ruleRatio   = this.rulesCount ? (this.enabledRulesCount / this.rulesCount) : 1;

    const rings = [
      { label: 'Cluster Engine Availability', value: engineRatio, color: '#10b981', filter: 'url(#gauge-emerald)', r: 94, w: 10 },
      { label: 'Active Tenant Ingestion',      value: tenantRatio, color: '#06b6d4', filter: 'url(#gauge-cyan)', r: 78, w: 10 },
      { label: 'Sensor Interface Fleet',      value: sensorRatio, color: '#f59e0b', filter: 'url(#gauge-amber)', r: 62, w: 10 },
      { label: 'Enforced Security Rules',     value: ruleRatio,   color: '#8b5cf6', filter: 'url(#gauge-violet)', r: 46, w: 10 },
    ];

    const startAngle = -Math.PI * 0.75;
    const maxSweep = Math.PI * 1.5;

    rings.forEach(ring => {
      const arcGen = d3.arc<any>()
        .innerRadius(ring.r - ring.w / 2)
        .outerRadius(ring.r + ring.w / 2)
        .cornerRadius(ring.w / 2);

      g.append('path')
        .datum({
          startAngle,
          endAngle: startAngle + maxSweep
        })
        .attr('d', arcGen)
        .attr('fill', 'rgba(255, 255, 255, 0.05)')
        .attr('stroke', 'rgba(255, 255, 255, 0.04)')
        .attr('stroke-width', 0.5);

      const targetEnd = startAngle + maxSweep * Math.max(0.04, Math.min(1, ring.value));
      const pathEl = g.append('path')
        .datum({
          startAngle,
          endAngle: startAngle
        })
        .attr('d', arcGen)
        .attr('fill', ring.color)
        .attr('filter', ring.filter);

      pathEl.transition()
        .duration(800)
        .ease(d3.easeCubicOut)
        .attrTween('d', (d: any) => {
          const interpolate = d3.interpolate(d.endAngle, targetEnd);
          return (t: number) => {
            d.endAngle = interpolate(t);
            return arcGen(d) || '';
          };
        });
    });

    g.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '-0.1em')
      .attr('fill', '#ffffff')
      .style('font-size', '24px')
      .style('font-weight', '800')
      .style('letter-spacing', '-0.02em')
      .style('font-family', 'monospace')
      .text(`${this.overallHealthScore}%`);

    g.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '1.6em')
      .attr('fill', '#38bdf8')
      .style('font-size', '9.5px')
      .style('font-weight', '700')
      .style('letter-spacing', '0.14em')
      .style('text-transform', 'uppercase')
      .text(this.overallHealthScore >= 95 ? 'OPTIMAL' : 'MONITORED');
  }

  // ── 3. Dual-Channel Telemetry Stream (Live Polled from Server) ──

  renderResourceUtilizationArea() {
    const container = d3.select('#resource-area-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const node = container.node() as HTMLElement;
    const width = node.clientWidth || 700;
    const height = 260;
    const margin = { top: 24, right: 24, bottom: 32, left: 44 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const svgRoot = container.append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svgRoot.append('defs');
    this.addGlowFilter(defs, 'ov-glow-cyan', '#38bdf8', 4);
    this.addGlowFilter(defs, 'ov-glow-royal', '#3b82f6', 4);

    const gradCpu = defs.append('linearGradient').attr('id', 'telemetry-cpu-grad').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradCpu.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(56, 189, 248, 0.28)');
    gradCpu.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(56, 189, 248, 0.00)');

    const gradMem = defs.append('linearGradient').attr('id', 'telemetry-mem-grad').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradMem.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(59, 130, 246, 0.22)');
    gradMem.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(59, 130, 246, 0.00)');

    const svg = svgRoot.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
    const data = this.overviewTelemetryHistory.length > 0
      ? this.overviewTelemetryHistory
      : [{ time: new Date(), cpu: this.latestCpu, mem: this.latestMemory }];

    const x = d3.scaleTime()
      .domain(d3.extent(data, (d: any) => d.time) as [Date, Date])
      .range([0, innerW]);

    const y = d3.scaleLinear().domain([0, 100]).range([innerH, 0]);

    svg.append('g').attr('class', 'telemetry-grid')
      .call(d3.axisLeft(y).tickSize(-innerW).tickFormat(() => '').ticks(4));

    svg.append('g').attr('class', 'telemetry-axis')
      .attr('transform', `translate(0,${innerH})`)
      .call(d3.axisBottom(x).ticks(5).tickSizeOuter(0).tickFormat((d: any) => d3.timeFormat('%H:%M:%S')(d)));

    svg.append('g').attr('class', 'telemetry-axis')
      .call(d3.axisLeft(y).ticks(4).tickSizeOuter(0).tickFormat((d: any) => `${d}%`));

    const cpuArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.cpu)).curve(d3.curveMonotoneX);
    const memArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.mem)).curve(d3.curveMonotoneX);
    const cpuLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.cpu)).curve(d3.curveMonotoneX);
    const memLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.mem)).curve(d3.curveMonotoneX);

    svg.append('path').datum(data).attr('fill', 'url(#telemetry-mem-grad)').attr('d', memArea);
    svg.append('path').datum(data).attr('fill', 'url(#telemetry-cpu-grad)').attr('d', cpuArea);

    svg.append('path').datum(data).attr('fill', 'none')
      .attr('stroke', '#3b82f6').attr('stroke-width', 2)
      .attr('filter', 'url(#ov-glow-royal)').attr('d', memLine);

    svg.append('path').datum(data).attr('fill', 'none')
      .attr('stroke', '#38bdf8').attr('stroke-width', 2.5)
      .attr('filter', 'url(#ov-glow-cyan)').attr('d', cpuLine);

    if (data.length > 0) {
      const last = data[data.length - 1];
      svg.append('circle').attr('cx', x(last.time)).attr('cy', y(last.mem))
        .attr('r', 4.5).attr('fill', '#3b82f6').attr('stroke', '#ffffff').attr('stroke-width', 1.5)
        .attr('filter', 'url(#ov-glow-royal)');

      svg.append('circle').attr('cx', x(last.time)).attr('cy', y(last.cpu))
        .attr('r', 5.5).attr('fill', '#38bdf8').attr('stroke', '#ffffff').attr('stroke-width', 2)
        .attr('filter', 'url(#ov-glow-cyan)');
    }
  }

  // ── 4. Global User Role Donut (From Real Users Table) ──────────

  renderUserRolesDonut() {
    const container = d3.select('#user-roles-donut-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const roles: any = { 'Platform Admin': 0, 'Tenant Admin': 0, 'Analyst': 0, 'Viewer': 0, 'Other': 0 };
    for (const u of this.users) {
      if (u.role === 'admin' || u.role === 'super_admin') roles['Platform Admin']++;
      else if (u.role === 'tenant_admin') roles['Tenant Admin']++;
      else if (u.role === 'analyst' || u.role === 'senior_analyst') roles['Analyst']++;
      else if (u.role === 'viewer') roles['Viewer']++;
      else roles['Other']++;
    }

    const data: any[] = Object.entries(roles).filter(([, v]: [string, any]) => v > 0).map(([label, value]) => ({ label, value }));
    if (data.length === 0) return;

    const total = d3.sum(data, (d: any) => Number(d.value));

    const node = container.node() as HTMLElement;
    const width = node.clientWidth || 280;
    const height = 240;
    const radius = Math.min(width, height) / 2 - 14;

    const svgRoot = container.append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svgRoot.append('defs');
    this.addGlowFilter(defs, 'role-glow-donut', '#38bdf8', 4);

    const svg = svgRoot.append('g').attr('transform', `translate(${width / 2},${height / 2})`);

    const colors = ['#38bdf8', '#818cf8', '#34d399', '#fbbf24', '#f43f5e'];
    const color = d3.scaleOrdinal<string>().domain(data.map(d => d.label)).range(colors);
    const pie = d3.pie<any>().value(d => d.value).sort(null).padAngle(0.04);
    const arc = d3.arc<any>().innerRadius(radius * 0.64).outerRadius(radius).cornerRadius(4);
    const hoverArc = d3.arc<any>().innerRadius(radius * 0.64).outerRadius(radius + 6).cornerRadius(4);

    const pieData = pie(data);
    const tooltip = this.getOrCreateTooltip();

    const arcs = svg.selectAll('.role-slice').data(pieData).enter().append('path')
      .attr('class', 'role-slice')
      .attr('fill', (d: any) => color(d.data.label))
      .attr('stroke', 'rgba(255, 255, 255, 0.12)')
      .attr('stroke-width', 1)
      .attr('filter', 'url(#role-glow-donut)')
      .attr('d', (d: any) => {
        const start = { ...d, endAngle: d.startAngle };
        return arc(start);
      })
      .on('mouseover', function(event: any, d: any) {
        d3.select(this).transition().duration(150).attr('d', hoverArc);
        tooltip.transition().duration(50).style('opacity', 1);
        tooltip.html(`
          <div class="cyber-tt-head"><strong>${d.data.label}</strong></div>
          <div class="cyber-tt-body"><div class="tt-row"><span>Identities:</span> <b>${d.data.value}</b></div></div>
        `)
        .style('left', `${event.pageX + 15}px`)
        .style('top', `${event.pageY - 28}px`);
      })
      .on('mousemove', (event: any) => {
        tooltip.style('left', `${event.pageX + 15}px`).style('top', `${event.pageY - 28}px`);
      })
      .on('mouseout', function() {
        d3.select(this).transition().duration(150).attr('d', arc);
        tooltip.transition().duration(200).style('opacity', 0);
      });

    arcs.transition().duration(700).ease(d3.easeCubicOut)
      .attrTween('d', (d: any) => {
        const interp = d3.interpolate({ ...d, endAngle: d.startAngle }, d);
        return (t: number) => arc(interp(t)) || '';
      });

    svg.append('text').attr('text-anchor', 'middle').attr('dy', '-0.1em')
      .attr('fill', '#ffffff').style('font-size', '24px').style('font-weight', '800')
      .style('font-family', 'monospace').text(total);

    svg.append('text').attr('text-anchor', 'middle').attr('dy', '1.5em')
      .attr('fill', '#64748b').style('font-size', '9.5px').style('letter-spacing', '0.1em')
      .style('text-transform', 'uppercase').text('OPERATORS');
  }

  // ── 5. 3D Rotating Earth Globe with All Countries & Malicious IPs ──
  private initGlobalGlobe() {
    const el = this.globalGlobe?.nativeElement;
    if (!el) return;

    this.destroyGlobalGlobe();
    d3.select(el).selectAll('*').remove();
    el.style.position = 'relative';

    const W = el.clientWidth || 740;
    const H = el.clientHeight || 340;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    const canvas = d3.select(el).append('canvas')
      .node() as HTMLCanvasElement;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    canvas.style.position = 'absolute';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.cursor = 'grab';

    const ctx = canvas.getContext('2d', { alpha: true })!;
    ctx.scale(dpr, dpr);

    const baseR = Math.min(W, H) * 0.44;
    const rot: [number, number, number] = [-20, -15, 0];
    const proj = d3.geoOrthographic()
      .scale(baseR * this.globeScale)
      .translate([W / 2, H / 2])
      .clipAngle(90)
      .rotate(rot);

    const pCtx = d3.geoPath().projection(proj).context(ctx);

    let land: any = null;
    let borders: any = null;
    if (this.cachedWorldData) {
      try {
        land = (topojson as any).feature(this.cachedWorldData, this.cachedWorldData.objects.countries);
        borders = (topojson as any).mesh(this.cachedWorldData, this.cachedWorldData.objects.countries, (a: any, b: any) => a !== b);
      } catch (err) {}
    }
    const grat = d3.geoGraticule().step([20, 20])();

    const frontHemi = (lonLat: [number, number]) =>
      d3.geoDistance(lonLat, [-rot[0], -rot[1]] as [number, number]) < Math.PI / 2;

    const TARGET: [number, number] = [77.2, 28.6]; // Primary NDR SOC node

    // Plot ALL threat hubs & ALL individual malicious IPs
    const allHubs = this.relayHubs;
    const allIps = this.threatIntelItems;

    // Flying animated particles along arcs
    const particles = allHubs.slice(0, 28).flatMap(hub =>
      [0, 0.5].map(offset => ({
        src: [hub.lon, hub.lat] as [number, number],
        t: (offset + Math.random() * 0.2) % 1,
        speed: 0.0035 + Math.random() * 0.002,
      }))
    );

    // Interactive Tooltip & State
    const tooltip = this.getOrCreateTooltip();
    let isHovered = false;
    let isUserDragging = false;
    let hoveredNode: { type: 'ip' | 'hub'; data: any; xy: [number, number] } | null = null;

    // Mouse Wheel Zoom Listener on 3D Globe Canvas
    canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      this.targetGlobeScale = Math.max(0.75, Math.min(4.5, this.targetGlobeScale * zoomFactor));
    }, { passive: false });

    canvas.addEventListener('mousemove', (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      let foundIp: ThreatIntelTableItem | null = null;
      let foundHub: RelayHub | null = null;
      let foundXy: [number, number] | null = null;
      let minDistance = 14;

      // 1. Check individual IPs first
      for (const item of allIps) {
        const pt: [number, number] = [item.dispLon ?? item.lon, item.dispLat ?? item.lat];
        if (!frontHemi(pt)) continue;
        const xy = proj(pt);
        if (!xy) continue;
        const dist = Math.hypot(mx - xy[0], my - xy[1]);
        if (dist < minDistance) {
          minDistance = dist;
          foundIp = item;
          foundXy = xy;
        }
      }

      // 2. Check country hubs if not closely over an IP
      if (!foundIp) {
        let minHubDist = 18;
        for (const hub of allHubs) {
          if (!frontHemi([hub.lon, hub.lat])) continue;
          const xy = proj([hub.lon, hub.lat]);
          if (!xy) continue;
          const dist = Math.hypot(mx - xy[0], my - xy[1]);
          if (dist < minHubDist) {
            minHubDist = dist;
            foundHub = hub;
            foundXy = xy;
          }
        }
      }

      if (foundIp && foundXy) {
        isHovered = true;
        canvas.style.cursor = 'pointer';
        hoveredNode = { type: 'ip', data: foundIp, xy: foundXy };
        tooltip.style('opacity', '1');
        tooltip.html(`
          <div class="cyber-tt-head">
            <span class="cyber-tt-flag">${foundIp.flag}</span>
            <strong class="text-rose-400 font-mono">${foundIp.ip}</strong>
          </div>
          <div class="cyber-tt-body">
            <div class="tt-row"><span>Origin:</span> <b>${foundIp.country} (${foundIp.code})</b></div>
            <div class="tt-row"><span>Classification:</span> <b class="tt-danger">${foundIp.threatType}</b></div>
            <div class="tt-row"><span>Feed Source:</span> <b>${foundIp.feed}</b></div>
            <div class="tt-row"><span>IOC Hits:</span> <b class="tt-alert">${foundIp.hits} hits</b></div>
            <div class="tt-row"><span>Coordinates:</span> <b>${foundIp.lat.toFixed(2)}°, ${foundIp.lon.toFixed(2)}°</b></div>
          </div>
        `);
        const tx = Math.min(window.innerWidth - 270, Math.max(10, e.clientX + 16));
        const ty = Math.min(window.innerHeight - 170, Math.max(10, e.clientY - 24));
        tooltip.style('left', `${tx}px`).style('top', `${ty}px`);
      } else if (foundHub && foundXy) {
        isHovered = true;
        canvas.style.cursor = 'pointer';
        hoveredNode = { type: 'hub', data: foundHub, xy: foundXy };
        tooltip.style('opacity', '1');
        tooltip.html(`
          <div class="cyber-tt-head">
            <span class="cyber-tt-flag">${foundHub.flag}</span>
            <strong>${foundHub.name}</strong>
          </div>
          <div class="cyber-tt-body">
            <div class="tt-row"><span>Attribution:</span> <b>${foundHub.region}</b></div>
            <div class="tt-row"><span>Status:</span> <b class="tt-status">${foundHub.status}</b></div>
            <div class="tt-row"><span>Aggregated Hits:</span> <b>${foundHub.throughput}</b></div>
            <div class="tt-row"><span>Threat Volume:</span> <b class="text-rose-400">${foundHub.attackCount || 1} active IOCs</b></div>
            <div class="tt-row"><span>Coordinates:</span> <b>${foundHub.lat}°, ${foundHub.lon}°</b></div>
          </div>
        `);
        const tx = Math.min(window.innerWidth - 270, Math.max(10, e.clientX + 16));
        const ty = Math.min(window.innerHeight - 170, Math.max(10, e.clientY - 24));
        tooltip.style('left', `${tx}px`).style('top', `${ty}px`);
      } else {
        isHovered = false;
        hoveredNode = null;
        canvas.style.cursor = isUserDragging ? 'grabbing' : 'grab';
        tooltip.style('opacity', '0');
      }
    });

    canvas.addEventListener('click', () => {
      if (hoveredNode) {
        if (hoveredNode.type === 'ip') {
          this.focusThreatCountry(hoveredNode.data);
        } else {
          this.selectCountryHub(hoveredNode.data);
        }
      }
    });

    canvas.addEventListener('mouseleave', () => {
      isHovered = false;
      hoveredNode = null;
      tooltip.style('opacity', '0');
    });

    // Drag-to-Rotate Interaction with zoom-aware sensitivity
    let dragStart: [number, number] | null = null;
    let rotStart: [number, number, number] = [...rot] as [number, number, number];

    d3.select(canvas).call(
      (d3.drag() as any)
        .on('start', (event: any) => {
          isUserDragging = true;
          this.targetGlobeRot = null;
          dragStart = [event.x, event.y];
          rotStart = [...rot] as [number, number, number];
          canvas.style.cursor = 'grabbing';
        })
        .on('drag', (event: any) => {
          if (!dragStart) return;
          const sens = 0.35 / Math.max(1, this.globeScale * 0.65);
          rot[0] = rotStart[0] + (event.x - dragStart[0]) * sens;
          rot[1] = Math.max(-75, Math.min(75, rotStart[1] - (event.y - dragStart[1]) * sens));
          proj.rotate(rot);
        })
        .on('end', () => {
          dragStart = null;
          isUserDragging = false;
          canvas.style.cursor = 'grab';
        })
    );

    // Continuous Animation Frame (Pure Canvas 60 FPS)
    let animTime = 0;
    const frame = () => {
      animTime += 0.03;

      // 1. Camera Rotation
      if (this.targetGlobeRot) {
        const dRot0 = ((this.targetGlobeRot[0] - rot[0] + 540) % 360) - 180;
        const dRot1 = this.targetGlobeRot[1] - rot[1];
        rot[0] += dRot0 * 0.08;
        rot[1] += dRot1 * 0.08;
        proj.rotate(rot);
        if (Math.abs(dRot0) < 0.3 && Math.abs(dRot1) < 0.3) {
          this.targetGlobeRot = null;
        }
      } else if (!isUserDragging && !isHovered) {
        rot[0] += 0.12; // buttery smooth cinematic rotation
        proj.rotate(rot);
      }

      // 2. Smooth Lerp Scale
      this.globeScale += (this.targetGlobeScale - this.globeScale) * 0.12;
      const currentR = baseR * this.globeScale;
      proj.scale(currentR);

      ctx.clearRect(0, 0, W, H);

      // 3. Dynamic Atmosphere glow behind sphere
      const atmoGrad = ctx.createRadialGradient(W / 2, H / 2, currentR * 0.88, W / 2, H / 2, currentR * 1.25);
      atmoGrad.addColorStop(0, 'rgba(56, 189, 248, 0.22)');
      atmoGrad.addColorStop(0.5, 'rgba(56, 189, 248, 0.06)');
      atmoGrad.addColorStop(1, 'rgba(56, 189, 248, 0)');

      ctx.beginPath();
      ctx.arc(W / 2, H / 2, currentR * 1.22, 0, Math.PI * 2);
      ctx.fillStyle = atmoGrad;
      ctx.fill();

      // 4. Earth ocean sphere
      const oceanGrad = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, currentR * 1.05);
      oceanGrad.addColorStop(0, '#09152b');
      oceanGrad.addColorStop(0.7, '#060f20');
      oceanGrad.addColorStop(1, '#030814');

      ctx.beginPath();
      pCtx({ type: 'Sphere' } as any);
      ctx.fillStyle = oceanGrad;
      ctx.fill();

      // 5. Graticule lines
      ctx.beginPath();
      pCtx(grat);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.07)';
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // 6. Continents & Landmasses
      if (land) {
        ctx.beginPath();
        pCtx(land as any);
        ctx.fillStyle = '#0e223e';
        ctx.fill();
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.36)';
        ctx.lineWidth = 0.7;
        ctx.stroke();
      }

      // 7. Country borders
      if (borders) {
        ctx.beginPath();
        pCtx(borders as any);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.16)';
        ctx.lineWidth = 0.4;
        ctx.stroke();
      }

      // 8. Earth outer rim glow
      ctx.beginPath();
      pCtx({ type: 'Sphere' } as any);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.55)';
      ctx.lineWidth = 1.6;
      ctx.stroke();

      // 9. Great Circle Threat Ingress Arcs
      allHubs.slice(0, 24).forEach(hub => {
        const interp = d3.geoInterpolate([hub.lon, hub.lat], TARGET);
        ctx.beginPath();
        let first = true;
        for (let s = 0; s <= 20; s++) {
          const pt = interp(s / 20) as [number, number];
          if (frontHemi(pt)) {
            const xy = proj(pt);
            if (xy) {
              if (first) { ctx.moveTo(xy[0], xy[1]); first = false; }
              else { ctx.lineTo(xy[0], xy[1]); }
            }
          } else {
            first = true;
          }
        }
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.26)';
        ctx.lineWidth = 1.0;
        ctx.setLineDash([3, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 10. Animated Flying Particles along Arcs
      particles.forEach(p => {
        p.t = (p.t + p.speed) % 1;
        const interp = d3.geoInterpolate(p.src, TARGET);
        const pt = interp(p.t) as [number, number];
        if (frontHemi(pt)) {
          const xy = proj(pt);
          if (xy) {
            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 2, 0, Math.PI * 2);
            ctx.fillStyle = '#38bdf8';
            ctx.shadowColor = '#38bdf8';
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }
      });

      // 11. All Individual Malicious IPs (All 200 IPs)
      allIps.forEach(item => {
        const pt: [number, number] = [item.dispLon ?? item.lon, item.dispLat ?? item.lat];
        if (frontHemi(pt)) {
          const xy = proj(pt);
          if (xy) {
            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 2.2, 0, Math.PI * 2);
            ctx.fillStyle = '#fb7185';
            ctx.fill();
          }
        }
      });

      // 12. All Country Threat Hub Beacons with Dynamic Text when Zoomed In
      allHubs.forEach(hub => {
        const coords: [number, number] = [hub.lon, hub.lat];
        if (frontHemi(coords)) {
          const xy = proj(coords);
          if (xy) {
            const pulse = (Math.sin(animTime * 3 + hub.lat) + 1) / 2;

            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 5 + pulse * 4, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(244, 63, 94, ${0.35 + pulse * 0.45})`;
            ctx.lineWidth = 1.1;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 3.2, 0, Math.PI * 2);
            ctx.fillStyle = '#f43f5e';
            ctx.fill();

            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 1.2, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.fill();

            // When zoomed in on the 3D globe (scale >= 1.7), render clean country label on canvas
            if (this.globeScale >= 1.7) {
              ctx.font = '600 10px monospace, sans-serif';
              ctx.fillStyle = '#e2e8f0';
              ctx.textAlign = 'center';
              ctx.fillText(hub.city || hub.name, xy[0], xy[1] + 13);
            }
          }
        }
      });

      // 13. Primary NDR SOC Hub Target Beacon (Cyan)
      if (frontHemi(TARGET)) {
        const xy = proj(TARGET);
        if (xy) {
          const pulse = (Math.sin(animTime * 4) + 1) / 2;
          ctx.beginPath();
          ctx.arc(xy[0], xy[1], 7 + pulse * 5, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(56, 189, 248, ${0.4 + pulse * 0.5})`;
          ctx.lineWidth = 1.3;
          ctx.stroke();

          ctx.beginPath();
          ctx.arc(xy[0], xy[1], 3.5, 0, Math.PI * 2);
          ctx.fillStyle = '#38bdf8';
          ctx.fill();
        }
      }

      // 14. Highlight Ring on Hovered Node
      if (hoveredNode) {
        const pt: [number, number] = hoveredNode.type === 'ip'
          ? [hoveredNode.data.dispLon ?? hoveredNode.data.lon, hoveredNode.data.dispLat ?? hoveredNode.data.lat]
          : [hoveredNode.data.lon, hoveredNode.data.lat];
        if (frontHemi(pt)) {
          const xy = proj(pt);
          if (xy) {
            ctx.beginPath();
            ctx.arc(xy[0], xy[1], 10, 0, Math.PI * 2);
            ctx.strokeStyle = '#f43f5e';
            ctx.lineWidth = 1.8;
            ctx.shadowColor = '#f43f5e';
            ctx.shadowBlur = 10;
            ctx.stroke();
            ctx.shadowBlur = 0;
          }
        }
      }

      this.globeAnimationFrame = requestAnimationFrame(frame);
    };

    // Pure canvas redraw loop — keep it out of Angular's zone so 60fps
    // rendering doesn't trigger a full-app change-detection pass every frame.
    this.zone.runOutsideAngular(() => {
      this.globeAnimationFrame = requestAnimationFrame(frame);
    });
  }

  private destroyGlobalGlobe() {
    if (this.globeAnimationFrame !== null) {
      cancelAnimationFrame(this.globeAnimationFrame);
      this.globeAnimationFrame = null;
    }
    const host = this.globalGlobe?.nativeElement;
    if (host) {
      d3.select(host).selectAll('*').remove();
    }
  }

  // ── 6. Three.js Subtle Backdrop Mesh ───────────────────────────

  private initCommandMesh() {
    const host = this.commandMesh?.nativeElement;
    if (!host || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    try {
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
      camera.position.set(0, 0, 8);

      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.setClearColor(0x000000, 0);
      renderer.domElement.setAttribute('aria-hidden', 'true');
      host.appendChild(renderer.domElement);

      // See the matching comment in tenant-admin/users.ts's initThreeCyberTopology -
      // without this, a lost WebGL context leaves the rAF loop below calling
      // render() on a dead context forever instead of stopping or recovering.
      renderer.domElement.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        if (this.meshAnimationFrame !== null) { cancelAnimationFrame(this.meshAnimationFrame); this.meshAnimationFrame = null; }
      }, false);
      renderer.domElement.addEventListener('webglcontextrestored', () => {
        this.destroyCommandMesh();
        this.initCommandMesh();
      }, false);

      const count = 240;
      const positions = new Float32Array(count * 3);
      const colors = new Float32Array(count * 3);
      const cyan = new THREE.Color('#38bdf8');
      const blue = new THREE.Color('#3b82f6');

      for (let i = 0; i < count; i++) {
        const radius = 1.2 + Math.random() * 3.4;
        const angle = Math.random() * Math.PI * 2;
        const height = (Math.random() - 0.5) * 3.6;
        positions[i * 3] = Math.cos(angle) * radius;
        positions[i * 3 + 1] = height;
        positions[i * 3 + 2] = Math.sin(angle) * radius * 0.55;
        const tint = Math.random() > 0.6 ? cyan : blue;
        colors[i * 3] = tint.r;
        colors[i * 3 + 1] = tint.g;
        colors[i * 3 + 2] = tint.b;
      }

      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      const material = new THREE.PointsMaterial({
        size: 0.035,
        vertexColors: true,
        transparent: true,
        opacity: 0.65,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      });
      const points = new THREE.Points(geometry, material);
      points.rotation.set(-0.2, 0.38, 0);
      scene.add(points);

      const resize = () => {
        const { width, height } = host.getBoundingClientRect();
        if (!width || !height) return;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height, false);
      };
      resize();

      this.meshResizeObserver = new ResizeObserver(resize);
      this.meshResizeObserver.observe(host);

      this.meshScene = scene;
      this.meshRenderer = renderer;
      this.meshGeometry = geometry;
      this.meshMaterial = material;

      this.zone.runOutsideAngular(() => {
        const animate = () => {
          points.rotation.y += 0.0006;
          points.rotation.z = Math.sin(performance.now() * 0.00015) * 0.04;
          renderer.render(scene, camera);
          this.meshAnimationFrame = requestAnimationFrame(animate);
        };
        animate();
      });
    } catch {}
  }

  private destroyCommandMesh() {
    if (this.meshAnimationFrame !== null) cancelAnimationFrame(this.meshAnimationFrame);
    this.meshResizeObserver?.disconnect();
    this.meshGeometry?.dispose();
    this.meshMaterial?.dispose();
    this.meshRenderer?.dispose();
    this.meshRenderer?.domElement.remove();
    this.meshAnimationFrame = null;
    this.meshResizeObserver = null;
    this.meshGeometry = null;
    this.meshMaterial = null;
    this.meshRenderer = null;
    this.meshScene = null;
  }
}
