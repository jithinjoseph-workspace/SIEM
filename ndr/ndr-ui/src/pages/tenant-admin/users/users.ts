import {
  Component, Input, OnInit, OnDestroy, AfterViewInit, ChangeDetectionStrategy,
  signal, computed, effect, ViewEncapsulation, ElementRef, ViewChild
} from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Users as UsersLucide, UserPlus, ShieldCheck, Lock, Edit, Trash2, X, Save,
  Activity, ChartColumn, Shield, Search, ArrowUpDown, MoreVertical,
  LayoutDashboard, Bell, FileText, Radio, Network, Globe, Gem, Settings,
  UserCircle, ChevronRight, Server, FolderSearch, Bot, Cpu, Plus,
  AlertCircle, XCircle, ChevronDown, Check, RotateCcw,
  Database, ShieldAlert, ScrollText, Zap, Layers, Sparkles, TrendingUp
} from 'lucide-angular';
import { Api, SensorKey, SensorAssignment } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { TenantStatusService } from '../../../services/tenant-status/tenant-status';
import { Subscription } from 'rxjs';
import { BaseChartDirective } from 'ng2-charts';
import * as THREE from 'three';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
interface TenantUser {
  id: string;
  username: string;
  role: string;
  tenant_id: string;
  created_at?: string;
  active?: boolean;
  permissions?: string[] | string;
}

interface PermissionOption {
  key: string;
  label: string;
  description: string;
  icon: any;
  // features that unlock this page — empty means always visible
  requiredFeatures?: string[];
}

@Component({
  selector: 'app-users',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule, BaseChartDirective, DatePipe],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class UsersSection implements OnInit, OnDestroy, AfterViewInit {
  @Input() tenantId = '';
  @Input() tenantName = 'Organization';
  @Input() set tenantFeatures(v: string[]) { if (v?.length) this._tenantFeatures.set(v); }
  private readonly _tenantFeatures = signal<string[]>([]);

  UsersIcon        = UsersLucide;
  UserPlusIcon     = UserPlus;
  ShieldIcon       = ShieldCheck;
  LockIcon         = Lock;
  EditIcon         = Edit;
  TrashIcon        = Trash2;
  XIcon            = X;
  SaveIcon         = Save;
  ActivityIcon     = Activity;
  ChartIcon        = ChartColumn;
  ShieldIconAlt    = Shield;
  SearchIcon       = Search;
  SortIcon         = ArrowUpDown;
  MoreIcon         = MoreVertical;
  LayoutDashboardIcon = LayoutDashboard;
  BellIcon         = Bell;
  FileTextIcon     = FileText;
  RadioIcon        = Radio;
  NetworkIcon      = Network;
  GlobeIcon        = Globe;
  GemIcon          = Gem;
  SettingsIcon     = Settings;
  UserCircleIcon   = UserCircle;
  ChevronRightIcon = ChevronRight;
  ServerIcon       = Server;
  FolderSearchIcon = FolderSearch;
  BotIcon          = Bot;
  CpuIcon          = Cpu;
  PlusIcon         = Plus;
  AlertCircleIcon  = AlertCircle;
  XCircleIcon      = XCircle;
  ChevronDownIcon  = ChevronDown;
  CheckIcon        = Check;
  ZapIcon          = Zap;
  RotateCcwIcon    = RotateCcw;
  LayersIcon       = Layers;
  SparklesIcon     = Sparkles;
  TrendingUpIcon   = TrendingUp;

  // ── Three.js Viewport Reference ───────────────────────────────────────────
  @ViewChild('threeCanvasContainer', { static: false }) threeCanvasRef?: ElementRef<HTMLDivElement>;
  private threeRenderer?: THREE.WebGLRenderer;
  private threeScene?: THREE.Scene;
  private threeCamera?: THREE.PerspectiveCamera;
  private threeAnimId?: number;
  private threeResizeObs?: ResizeObserver;
  private threeMeshGroup?: THREE.Group;
  private coreMesh?: THREE.Mesh;
  private ring1?: THREE.Mesh;
  private ring2?: THREE.Mesh;
  private points?: THREE.Points;        // real users — person sprite
  private sensorPoints?: THREE.Points;   // real sensors — chip sprite
  private assignmentLines?: THREE.LineSegments; // real user↔sensor access links
  private coreLines?: THREE.LineSegments;       // every endpoint → the inner core
  private energyPoints?: THREE.Points;          // traveling pulses along each spoke
  private spokeEnds: { x: number; y: number; z: number; phase: number }[] = [];
  private pulseRing?: THREE.Mesh;
  private pulseScale = 0;
  private pulseOpacity = 0;
  private isPointerDown = false;
  private prevPointerX = 0;
  private prevPointerY = 0;

  // Hover-to-inspect: which real user/sensor each mesh point corresponds
  // to, snapshotted at mesh-build time so indices always line up.
  private raycaster = new THREE.Raycaster();
  private mouseNdc = new THREE.Vector2();
  private meshUsersSnapshot: TenantUser[] = [];
  private meshSensorsSnapshot: SensorKey[] = [];
  // Stored so assignment lines can be rebuilt when sensorAssignments()
  // changes, without moving any dot or rebuilding the whole scene.
  private meshUserPositions?: Float32Array;
  private meshSensorPositions?: Float32Array;
  readonly hoveredNode = signal<{ type: 'user' | 'sensor'; name: string; sub: string; ip: string } | null>(null);
  readonly hoverTooltipPos = signal<{ x: number; y: number }>({ x: 0, y: 0 });
  // Real sensor IPs (derived from that sensor's own traffic) and real
  // user session IPs (from active logins) — see loadIngestStats() /
  // loadUserSessionIps().
  readonly sensorIps = signal<Record<string, string>>({});
  readonly userSessionIps = signal<Record<string, string>>({});

  // ── High-Tech Cockpit & 3D Signals ─────────────────────────────────────────
  readonly threeVisualMode        = signal<'full' | 'wireframe' | 'particles' | 'core'>('full');
  readonly threeSpeed             = signal<number>(1);
  readonly authTimeframe          = signal<'6h' | '12h' | '24h' | '7d'>('24h');
  readonly feedFilter             = signal<'all' | 'auth' | 'sensor' | 'policy'>('all');

  // Real events only. Seeded once from real history (account creation
  // timestamps + real active sessions — see seedLiveAuditFeed()), then
  // pushLiveEvent() prepends anything that actually happens this session
  // (user created/updated/deleted, sensor assigned). Never simulated.
  readonly liveAuditEvents = signal<any[]>([]);

  readonly filteredAuditEvents = computed(() => {
    const f = this.feedFilter();
    if (f === 'all') return this.liveAuditEvents();
    return this.liveAuditEvents().filter(e => e.type === f);
  });

  // ── 3D Card Interactive Parallax Tilt & Hologram Specular Tracking ──────
  onCardMouseMove(event: MouseEvent): void {
    const card = event.currentTarget as HTMLElement;
    if (!card) return;
    const rect = card.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const rotateX = ((y - centerY) / centerY) * -7.5;
    const rotateY = ((x - centerX) / centerX) * 7.5;
    card.style.setProperty('--rot-x', `${rotateX.toFixed(2)}deg`);
    card.style.setProperty('--rot-y', `${rotateY.toFixed(2)}deg`);
    card.style.setProperty('--shine-x', `${((x / rect.width) * 100).toFixed(1)}%`);
    card.style.setProperty('--shine-y', `${((y / rect.height) * 100).toFixed(1)}%`);
    card.style.setProperty('--shine-opacity', '1');
    card.style.setProperty('--hover-scale', '1.015');
    card.style.setProperty('--hover-lift', '10px');
  }

  onCardMouseLeave(event: MouseEvent): void {
    const card = event.currentTarget as HTMLElement;
    if (!card) return;
    card.style.setProperty('--rot-x', '0deg');
    card.style.setProperty('--rot-y', '0deg');
    card.style.setProperty('--shine-opacity', '0');
    card.style.setProperty('--hover-scale', '1');
    card.style.setProperty('--hover-lift', '0px');
  }

  // ── Core Signals ──────────────────────────────────────────────────────────
  readonly sensorKeys             = signal<SensorKey[]>([]);
  readonly sensorAssignments      = signal<SensorAssignment[]>([]);
  readonly sensorAssignLoading    = signal(false);
  readonly sensorAssignSaving     = signal(false);
  readonly pendingSensorSel       = signal<Record<string, string[]>>({});
  readonly sensorDropdownOpen     = signal<Record<string, boolean>>({});
  readonly activeSectionTab       = signal<'users' | 'sensors'>('users');
  readonly selectedUserIds        = signal(new Set<string>());
  readonly roleChartData          = signal<any>({ labels: [], datasets: [] });
  readonly statusChartData        = signal<any>({ labels: [], datasets: [] });
  readonly authTimelineChartData  = signal<any>({ labels: [], datasets: [] });
  readonly clearanceBarChartData  = signal<any>({ labels: [], datasets: [] });
  readonly searchTerm             = signal('');
  readonly sortField              = signal<keyof TenantUser | 'status'>('username');
  readonly sortAscending          = signal(true);
  readonly users               = signal<TenantUser[]>([]);
  readonly loading             = signal(false);
  readonly saving              = signal(false);
  readonly showForm            = signal(false);
  readonly editingUser         = signal<TenantUser | null>(null);
  readonly message             = signal('');
  readonly messageType         = signal<'success' | 'error'>('success');
  readonly usernameStatus      = signal<'idle' | 'checking' | 'available' | 'taken' | 'unavailable'>('idle');
  readonly usernameTouched     = signal(false);
  readonly passwordTouched     = signal(false);

  // Real ingestion telemetry for this tenant — see loadIngestStats().
  readonly ingestEventsTotal   = signal(0);
  readonly ingestEvents1h      = signal(0);
  readonly ingestHits1h        = signal(0);
  // Real per-sensor event counts (last 1h), keyed by sensor key_prefix.
  readonly sensorEventCounts   = signal<Record<string, number>>({});

  // Real threat telemetry for this tenant from /api/severity
  readonly criticalThreats     = signal(0);
  readonly highThreats         = signal(0);
  readonly mediumThreats       = signal(0);
  readonly lowThreats          = signal(0);

  // Real per-minute event counts for the last 60 minutes — see
  // loadIngestTimeline(). No simulated/randomized points.
  readonly sparklinePoints     = signal<number[]>([]);

  readonly currentThroughputEps = computed(() => {
    const e1h = this.ingestEvents1h();
    if (e1h <= 0) return '0.0 EPS';
    const eps = e1h / 3600;
    return eps >= 10 ? `${Math.round(eps)} EPS` : `${eps.toFixed(1)} EPS`;
  });

  readonly sparklineSvgPath = computed(() => {
    const pts = this.sparklinePoints();
    if (!pts || pts.length < 2) return '';
    const max = Math.max(...pts, 1);
    const min = Math.min(...pts, 0);
    const range = max - min || 1;
    const padX = 8;
    const chartWidth = 320 - (padX * 2);
    const height = 55;
    const padTop = 8;
    const padBottom = 8;
    const usableHeight = height - padTop - padBottom;

    const coords = pts.map((val, idx) => {
      const x = padX + (idx / (pts.length - 1)) * chartWidth;
      const y = height - padBottom - ((val - min) / range) * usableHeight;
      return { x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 };
    });

    let path = `M ${coords[0].x} ${coords[0].y}`;
    for (let i = 1; i < coords.length; i++) {
      const prev = coords[i - 1];
      const curr = coords[i];
      const cp1x = (prev.x + (curr.x - prev.x) / 2).toFixed(1);
      const cp1y = prev.y.toFixed(1);
      const cp2x = (prev.x + (curr.x - prev.x) / 2).toFixed(1);
      const cp2y = curr.y.toFixed(1);
      path += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${curr.x} ${curr.y}`;
    }
    return path;
  });

  readonly sparklineAreaPath = computed(() => {
    const linePath = this.sparklineSvgPath();
    if (!linePath) return '';
    const padX = 8;
    const chartWidth = 320 - (padX * 2);
    const firstX = padX;
    const lastX = padX + chartWidth;
    return `${linePath} L ${lastX} 55 L ${firstX} 55 Z`;
  });

  readonly sparklineLastPoint = computed(() => {
    const pts = this.sparklinePoints();
    if (!pts || pts.length === 0) return { x: 312, y: 30, val: 0 };
    const max = Math.max(...pts, 1);
    const min = Math.min(...pts, 0);
    const range = max - min || 1;
    const padX = 8;
    const chartWidth = 320 - (padX * 2);
    const height = 55;
    const padTop = 8;
    const padBottom = 8;
    const usableHeight = height - padTop - padBottom;
    const lastVal = pts[pts.length - 1];
    const y = height - padBottom - ((lastVal - min) / range) * usableHeight;
    return { x: padX + chartWidth, y: Math.round(y * 10) / 10, val: lastVal };
  });

  // ── Computed ──────────────────────────────────────────────────────────────

  readonly activeUsers        = computed(() => this.users().filter(u => u.active !== false).length);
  readonly analystUsers       = computed(() => this.users().filter(u => u.role === 'analyst' || u.role === 'senior_analyst').length);
  // 'analyst' role only — matches the donut chart's own "Analyst" segment,
  // which is computed separately in updateCharts() and does NOT include
  // senior_analyst (unlike analystUsers() above, kept for the seat bar).
  readonly pureAnalystUsers   = computed(() => this.users().filter(u => u.role === 'analyst').length);
  readonly seniorAnalystUsers = computed(() => this.users().filter(u => u.role === 'senior_analyst').length);
  readonly viewerUsers        = computed(() => this.users().filter(u => u.role === 'viewer').length);
  readonly assignableUsers    = computed(() => this.users());
  readonly accountHealthPct   = computed(() => {
    const total = this.users().length;
    return total > 0 ? Math.round((this.activeUsers() / total) * 100) : 100;
  });
  readonly suspendedUsers     = computed(() => this.users().length - this.activeUsers());
  readonly onlineSensorCount  = computed(() => this.sensorKeys().filter(s => s.active).length);
  readonly totalSensorCount   = computed(() => this.sensorKeys().length);

  readonly sensorCoveragePct   = computed(() => {
    const total = this.totalSensorCount();
    if (total === 0) return 100;
    return Math.round((this.onlineSensorCount() / total) * 100);
  });

  readonly totalThreatAlerts   = computed(() =>
    this.criticalThreats() + this.highThreats() + this.mediumThreats() + this.lowThreats()
  );

  readonly zeroTrustStatus     = computed<'OPTIMAL' | 'ELEVATED' | 'DEGRADED'>(() => {
    if (this.criticalThreats() > 0 || this.accountHealthPct() < 60) return 'DEGRADED';
    if (this.highThreats() > 0 || this.sensorCoveragePct() < 80) return 'ELEVATED';
    return 'OPTIMAL';
  });

  readonly postureScore        = computed(() => {
    let score = 100;
    score -= (this.criticalThreats() * 20);
    score -= (this.highThreats() * 8);
    if (this.sensorCoveragePct() < 100) {
      score -= Math.round((100 - this.sensorCoveragePct()) * 0.3);
    }
    if (this.suspendedUsers() > 0) {
      score -= (this.suspendedUsers() * 5);
    }
    return Math.max(10, Math.min(100, score));
  });

  readonly threatClearancePct  = computed(() => {
    if (this.criticalThreats() > 0) return Math.max(20, 100 - this.criticalThreats() * 25);
    if (this.highThreats() > 0) return Math.max(50, 100 - this.highThreats() * 10);
    return 100;
  });

  // One segment per real account — no fabricated seat cap.
  readonly seatBarSlots       = computed(() => Array.from({ length: Math.max(this.users().length, 1) }, (_, i) => i));

  readonly filteredAndSortedUsers = computed(() => {
    let result = this.users();
    const term = this.searchTerm();
    if (term) {
      const t = term.toLowerCase();
      result = result.filter(u =>
        u.username.toLowerCase().includes(t) ||
        this.getRoleLabel(u.role).toLowerCase().includes(t)
      );
    }
    const field = this.sortField();
    const asc   = this.sortAscending();
    return [...result].sort((a, b) => {
      let valA: any = a[field as keyof TenantUser];
      let valB: any = b[field as keyof TenantUser];
      if (field === 'status') { valA = a.active ? 1 : 0; valB = b.active ? 1 : 0; }
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      if (valA < valB) return asc ? -1 : 1;
      if (valA > valB) return asc ? 1 : -1;
      return 0;
    });
  });

  // ── Form state ────────────────────────────────────────────────────────────

  userForm = {
    username: '',
    password: '',
    role: 'analyst',
    active: true,
    permissions: ['dashboard', 'health'] as string[],
  };

  // ── Constants ─────────────────────────────────────────────────────────────

  readonly donutChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '76%',
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12,
        cornerRadius: 8, displayColors: true, boxWidth: 8, boxHeight: 8,
      }
    },
    elements: { arc: { borderWidth: 4, borderColor: '#171b37', borderRadius: 4, hoverOffset: 6 } }
  };

  readonly lineChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12, cornerRadius: 8
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
      }
    },
    elements: {
      line: { tension: 0.38, borderWidth: 3 },
      point: { radius: 3, hoverRadius: 6 }
    }
  };

  readonly barChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12, cornerRadius: 8
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#64748b', font: { family: 'Inter', size: 10.5 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
      }
    }
  };

  readonly permissionOptions: PermissionOption[] = [
    // NDR pages
    { key: 'dashboard',    label: 'Dashboard',       description: 'Operational overview',         icon: LayoutDashboard },
    { key: 'alerts',       label: 'Alerts',           description: 'Alert triage',                icon: Bell,            requiredFeatures: ['ndr', 'soar'] },
    { key: 'assets',       label: 'Assets',           description: 'Asset inventory',             icon: Server,          requiredFeatures: ['ndr', 'soar'] },
    { key: 'logs',         label: 'Network Logs',     description: 'Event records',               icon: FileText,        requiredFeatures: ['ndr'] },
    { key: 'live',         label: 'Live Stream',      description: 'Real-time activity',          icon: Radio,           requiredFeatures: ['ndr'] },
    { key: 'network-map',  label: 'Network Map',      description: 'Topology view',               icon: Network,         requiredFeatures: ['ndr'] },
    { key: 'intel',        label: 'Threat Intel',     description: 'IOC lookup',                  icon: Globe,           requiredFeatures: ['threat_intel'] },
    { key: 'health',       label: 'System Health',    description: 'Service status',              icon: Activity,        requiredFeatures: ['ndr'] },
    { key: 'rules',        label: 'Rules View',       description: 'Detection rules',             icon: Gem,             requiredFeatures: ['ndr'] },
    { key: 'evidence',     label: 'Evidence',         description: 'Artifact locker',             icon: FolderSearch,    requiredFeatures: ['ndr'] },
    { key: 'honeypots',    label: 'Honeypots',        description: 'Deception trap management',   icon: Shield,          requiredFeatures: ['ndr'] },
    { key: 'retrospective',label: 'Retrospective',    description: 'Historical rule re-scan',     icon: RotateCcw,       requiredFeatures: ['ndr'] },
    { key: 'soar',         label: 'SOAR View',        description: 'Automation visibility',       icon: Settings,        requiredFeatures: ['soar'] },
    { key: 'ai-activity',  label: 'AI Activity',      description: 'Aria interactions',           icon: Bot,             requiredFeatures: ['ai'] },
    { key: 'ai-report',    label: 'AI Report',        description: 'AI-generated reports',        icon: Bot,             requiredFeatures: ['ai'] },
    // SIEM pages
    { key: 'siem-dashboard', label: 'SIEM Dashboard', description: 'Security events overview',   icon: ShieldAlert,     requiredFeatures: ['siem'] },
    { key: 'siem-logs',      label: 'SIEM Logs',      description: 'Ingested log stream',         icon: ScrollText,      requiredFeatures: ['siem'] },
    { key: 'siem-sources',   label: 'SIEM Sources',   description: 'Log source management',       icon: Database,        requiredFeatures: ['siem'] },
  ];

  private readonly allPermissionCategories = [
    { title: 'CORE',       keys: ['dashboard', 'alerts', 'assets'] },
    { title: 'NETWORK',    keys: ['logs', 'network-map', 'live'] },
    { title: 'SECURITY',   keys: ['intel', 'rules', 'evidence'] },
    { title: 'ENFORCE',    keys: ['honeypots', 'retrospective'] },
    { title: 'OPERATIONS', keys: ['health', 'soar', 'ai-activity', 'ai-report'] },
    { title: 'SIEM',       keys: ['siem-dashboard', 'siem-logs', 'siem-sources'] },
  ];

  // ── License-aware permission computed signals ──────────────────────────────
  // Using computed() so these only recompute when _tenantFeatures changes,
  // not on every change-detection cycle like a plain getter would.

  readonly permissionCategories = computed(() => {
    const feats = this._tenantFeatures();
    const licensed = this.permissionOptions.filter(p => {
      if (!p.requiredFeatures || p.requiredFeatures.length === 0) return true;
      // OR logic: page is accessible if tenant has ANY of the required features
      return p.requiredFeatures.some(f => feats.includes(f));
    });
    return this.allPermissionCategories
      .map(cat => ({
        title: cat.title,
        options: cat.keys.map(k => licensed.find(p => p.key === k)!).filter(Boolean),
      }))
      .filter(cat => cat.options.length > 0);
  });

  readonly roleOptions = [
    { value: 'analyst',        label: 'Analyst',        tier: 'blue' },
    { value: 'senior_analyst', label: 'Senior Analyst', tier: 'violet' },
    { value: 'viewer',         label: 'Viewer',         tier: 'slate' },
  ];

  // ── Private internals ─────────────────────────────────────────────────────

  private usernameTimer: ReturnType<typeof setTimeout> | null = null;
  private usernameCheckSub: Subscription | null = null;
  private messageTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly usernamePattern = /^[A-Za-z0-9._-]+$/;
  private permLabelsCache = new Map<string, string[]>();
  // Lazy document click listener — only attached while a sensor dropdown is open
  private docClickListener: (() => void) | null = null;
  private telemetryTickerTimer: any = null;

  trackByUserId(_: number, user: TenantUser) { return user.id; }
  trackByIndex(i: number)                    { return i; }

  constructor(private api: Api, private auth: AuthService, private tenantStatus: TenantStatusService) {
    // Mirrors the shared poll's sensor-keys signal instead of this component
    // calling getSensorKeys() itself - that used to fire in parallel with
    // this same poll on every page load, a genuinely redundant fetch.
    // startPolling() is idempotent (main.ts's tenant-status.ts guards it),
    // so calling it here too is safe whether or not a parent already did.
    effect(() => {
      const keys = this.tenantStatus.sensorKeys();
      if (!this.tenantStatus.sensorKeysLoaded()) return;
      const tid = this.tenantId;
      this.sensorKeys.set(keys.filter((k: any) => k.tenant_id === tid && k.active !== false));
      this.sensorsLoaded = true;
      this.maybeInitTopology();
    });
  }

  ngOnInit() {
    if (!this.tenantId) {
      const user = this.auth.getUser();
      this.tenantId = user?.tenant_id || 'default';
      if (!this.tenantName || this.tenantName === 'Organization') {
        this.tenantName = (this.tenantId.split(/[-_]/).filter(Boolean)
          .map((p: string) => p.charAt(0).toUpperCase() + p.slice(1)).join(' ')) || 'Organization';
      }
    }
    // @Input() tenantFeatures is bound by the parent (TenantAdmin) which already
    // fetches the live value. Only seed from JWT here as a fallback for cases where
    // this component is loaded as a standalone route without a parent binding.
    if (!this._tenantFeatures().length) {
      const jwtFeats = this.auth.getTenantFeatures();
      this._tenantFeatures.set(jwtFeats.length ? jwtFeats : ['ndr']);
    }
    this.loadUsers();
    this.loadSensorData();
    this.loadIngestStats();
    this.loadIngestTimeline();
    this.startIngestRefresh();
  }

  loadIngestStats() {
    this.api.getStats().subscribe({
      next: (stats: any) => {
        this.ingestEventsTotal.set(Number(stats?.events_total) || 0);
        this.ingestEvents1h.set(Number(stats?.events_1h) || 0);
        this.ingestHits1h.set(Number(stats?.hits_1h) || 0);
      },
      error: reportRxjsError,
    });
    this.api.getSeverity().subscribe({
      next: (sev: any) => {
        this.criticalThreats.set(Number(sev?.critical) || 0);
        this.highThreats.set(Number(sev?.high) || 0);
        this.mediumThreats.set(Number(sev?.medium) || 0);
        this.lowThreats.set(Number(sev?.low) || 0);
      },
      error: reportRxjsError,
    });
    this.api.getSensorEventCounts().subscribe({
      next: (counts) => this.sensorEventCounts.set(counts || {}),
      error: reportRxjsError,
    });
    this.api.getSensorRecentIps().subscribe({
      next: (ips) => this.sensorIps.set(ips || {}),
      error: reportRxjsError,
    });
  }

  /** Real per-minute event history for the last 60 minutes — no simulation. */
  loadIngestTimeline() {
    this.api.getStatsTimeline().subscribe({
      next: (points) => this.sparklinePoints.set(points || []),
      error: reportRxjsError,
    });
  }

  /** Periodic re-fetch of real data only — no client-side randomness.
   *  30s (not 15s) since this fires 5 real HTTP calls per tick and this
   *  panel doesn't need near-real-time granularity. */
  startIngestRefresh() {
    if (this.telemetryTickerTimer) clearInterval(this.telemetryTickerTimer);
    this.telemetryTickerTimer = setInterval(() => {
      this.loadIngestStats();
      this.loadIngestTimeline();
    }, 30000);
  }

  /** A soft radial-gradient sprite texture, reused for the core's ambient
   *  glow and for each traveling energy particle. */
  private makeGlowTexture(): THREE.CanvasTexture {
    const size = 128;
    const c = size / 2;
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d')!;
    const grad = ctx.createRadialGradient(c, c, 0, c, c, c);
    grad.addColorStop(0, 'rgba(255,255,255,0.9)');
    grad.addColorStop(0.35, 'rgba(255,255,255,0.35)');
    grad.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, size, size);
    const tex = new THREE.CanvasTexture(canvas);
    tex.needsUpdate = true;
    return tex;
  }

  /** A small canvas-drawn icon sprite so account vs. sensor endpoints are
   *  recognizable by shape, not just color — a person glyph for accounts,
   *  a chip/radio glyph for sensors. A soft outer glow keeps each icon
   *  readable against the dark additive-blended scene. */
  private makeDotTexture(shape: 'person' | 'chip'): THREE.CanvasTexture {
    const size = 64;
    const c = size / 2;
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d')!;

    // Soft outer glow halo so the icon pops against the 3D scene.
    const glow = ctx.createRadialGradient(c, c, size * 0.14, c, c, size * 0.5);
    glow.addColorStop(0, 'rgba(255,255,255,0.55)');
    glow.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, size, size);

    ctx.fillStyle = '#ffffff';
    ctx.strokeStyle = '#ffffff';

    if (shape === 'person') {
      // Head
      ctx.beginPath();
      ctx.arc(c, size * 0.35, size * 0.14, 0, Math.PI * 2);
      ctx.fill();
      // Shoulders
      ctx.beginPath();
      ctx.arc(c, size * 0.86, size * 0.28, Math.PI, 0, false);
      ctx.fill();
    } else {
      // Chip body
      const bodyR = size * 0.19;
      const bx = c - bodyR, by = c - bodyR, bw = bodyR * 2, bh = bodyR * 2;
      ctx.lineWidth = size * 0.045;
      ctx.beginPath();
      (ctx as any).roundRect ? (ctx as any).roundRect(bx, by, bw, bh, size * 0.04) : ctx.rect(bx, by, bw, bh);
      ctx.stroke();
      // Center dot
      ctx.beginPath();
      ctx.arc(c, c, size * 0.06, 0, Math.PI * 2);
      ctx.fill();
      // Four pins
      const pinLen = size * 0.11;
      ctx.lineWidth = size * 0.04;
      [[0, -1], [0, 1], [-1, 0], [1, 0]].forEach(([dx, dy]) => {
        ctx.beginPath();
        ctx.moveTo(c + dx * bodyR, c + dy * bodyR);
        ctx.lineTo(c + dx * (bodyR + pinLen), c + dy * (bodyR + pinLen));
        ctx.stroke();
      });
    }

    const tex = new THREE.CanvasTexture(canvas);
    tex.needsUpdate = true;
    return tex;
  }

  /** Real events/1h for one sensor, keyed by its key_prefix. */
  sensorEventRate(sensor: SensorKey): number {
    return this.sensorEventCounts()[sensor.key_prefix] || 0;
  }

  /** Top 4 sensors by real event activity (active ones first, busiest first). */
  readonly topActiveSensors = computed(() => {
    const counts = this.sensorEventCounts();
    return [...this.sensorKeys()]
      .sort((a, b) => {
        if (a.active !== b.active) return a.active ? -1 : 1;
        return (counts[b.key_prefix] || 0) - (counts[a.key_prefix] || 0);
      })
      .slice(0, 4);
  });

  private viewReady = false;
  private usersLoaded = false;
  private sensorsLoaded = false;
  private assignmentsLoaded = false;

  ngAfterViewInit() {
    setTimeout(() => {
      this.viewReady = true;
      this.maybeInitTopology();
    }, 80);
  }

  /** Builds the 3D topology mesh only once the view AND all the real data
   *  it draws (users, sensors, sensor assignments) are ready — otherwise
   *  it would render with 0/stale counts and never rebuild
   *  (initThreeCyberTopology no-ops once a renderer already exists). */
  private maybeInitTopology() {
    if (this.viewReady && this.usersLoaded && this.sensorsLoaded && this.assignmentsLoaded) {
      this.initThreeCyberTopology();
    }
  }

  ngOnDestroy() {
    this.clearUsernameCheck();
    this.removeDocClickListener();
    if (this.telemetryTickerTimer) clearInterval(this.telemetryTickerTimer);
    if (this.messageTimer) clearTimeout(this.messageTimer);
    this.disposeThreeCyberTopology();
  }

  resetThreeCamera() {
    if (this.threeMeshGroup) {
      this.threeMeshGroup.rotation.set(0.25, 0, 0);
    }
  }

  setThreeMode(mode: 'full' | 'wireframe' | 'particles' | 'core') {
    this.threeVisualMode.set(mode);
    if (!this.points || !this.sensorPoints || !this.coreMesh || !this.ring1 || !this.ring2) return;
    const setIconsVisible = (v: boolean) => {
      this.points!.visible = v;
      this.sensorPoints!.visible = v;
    };
    const setLinesVisible = (v: boolean) => {
      if (this.assignmentLines) this.assignmentLines.visible = v;
      if (this.coreLines) this.coreLines.visible = v;
      if (this.energyPoints) this.energyPoints.visible = v;
    };
    if (mode === 'full') {
      setIconsVisible(true);
      setLinesVisible(true);
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    } else if (mode === 'wireframe') {
      // "Mesh" — just the connection skeleton into the core, no icons
      setIconsVisible(false);
      setLinesVisible(true);
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    } else if (mode === 'particles') {
      setIconsVisible(true);
      setLinesVisible(true);
      this.coreMesh.visible = true;
      this.ring1.visible = false;
      this.ring2.visible = false;
    } else if (mode === 'core') {
      setIconsVisible(false);
      setLinesVisible(false);
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    }
  }

  setThreeSpeed(spd: number) {
    this.threeSpeed.set(spd);
  }

  triggerPulseWave() {
    this.pulseScale = 0.5;
    this.pulseOpacity = 0.95;
  }

  setFeedFilter(filter: 'all' | 'auth' | 'sensor' | 'policy') {
    this.feedFilter.set(filter);
  }

  /** Records a real thing that just happened — never fabricated. */
  private pushLiveEvent(type: 'auth' | 'sensor' | 'policy', title: string, subtitle: string, badge: string, badgeClass: string) {
    const newEvent = { id: Date.now(), type, title, subtitle, badge, badgeClass, time: 'Just now' };
    this.liveAuditEvents.update(list => [newEvent, ...list.slice(0, 9)]);
    this.triggerPulseWave();
  }

  setAuthTimeframe(tf: '6h' | '12h' | '24h' | '7d') {
    this.authTimeframe.set(tf);
    this.updateCharts();
  }

  switchTab(tab: 'users' | 'sensors') {
    // Leaving 'users' destroys #threeCanvasContainer (it's behind an
    // *ngIf), which rips the WebGL canvas out of the DOM without ever
    // disposing the Three.js renderer. Without this, coming back to
    // 'users' hits initThreeCyberTopology()'s "already built" guard,
    // which just resizes that now-orphaned canvas instead of rebuilding
    // — so the mesh stayed permanently blank after one tab round-trip.
    if (tab === 'sensors' && this.activeSectionTab() === 'users') {
      this.disposeThreeCyberTopology();
    }
    this.activeSectionTab.set(tab);
    if (tab === 'users') {
      setTimeout(() => this.initThreeCyberTopology(), 60);
    }
  }

  /** Fully tears down the 3D scene (see switchTab()) so the next
   *  initThreeCyberTopology() call does a complete fresh rebuild instead
   *  of no-op'ing against stale state. */
  private disposeThreeCyberTopology() {
    if (this.threeAnimId) cancelAnimationFrame(this.threeAnimId);
    if (this.threeResizeObs) this.threeResizeObs.disconnect();
    if (this.threeRenderer) {
      this.threeRenderer.dispose();
      this.threeRenderer.forceContextLoss();
    }
    this.threeAnimId = undefined;
    this.threeResizeObs = undefined;
    this.threeRenderer = undefined;
    this.threeScene = undefined;
    this.threeCamera = undefined;
    this.threeMeshGroup = undefined;
    this.coreMesh = undefined;
    this.ring1 = undefined;
    this.ring2 = undefined;
    this.points = undefined;
    this.sensorPoints = undefined;
    this.pulseRing = undefined;
    this.assignmentLines = undefined;
    this.coreLines = undefined;
    this.energyPoints = undefined;
    this.meshUserPositions = undefined;
    this.meshSensorPositions = undefined;
  }

  /** Redraws the real user↔sensor connection lines in the 3D mesh from the
   *  current sensorAssignments() — called whenever an assignment actually
   *  changes, not just once at scene build time (initThreeCyberTopology
   *  no-ops after the first build, so without this the lines would go
   *  stale the moment you assign/unassign a sensor). Reuses the same dot
   *  positions from the initial build so nothing jumps around. */
  private rebuildAssignmentLines() {
    if (!this.threeMeshGroup || !this.meshUserPositions || !this.meshSensorPositions) return;

    if (this.assignmentLines) {
      this.threeMeshGroup.remove(this.assignmentLines);
      this.assignmentLines.geometry.dispose();
      (this.assignmentLines.material as THREE.Material).dispose();
      this.assignmentLines = undefined;
    }

    const positions: number[] = [];
    const colors: number[] = [];
    const cLink = new THREE.Color(0x38bdf8);
    const userPos = this.meshUserPositions;
    const sensorPos = this.meshSensorPositions;
    for (const a of this.sensorAssignments()) {
      const uIdx = this.meshUsersSnapshot.findIndex(u => u.id === a.user_id);
      const sIdx = this.meshSensorsSnapshot.findIndex(s => s.key_prefix === a.sensor_id);
      if (uIdx === -1 || sIdx === -1) continue;
      positions.push(
        userPos[uIdx * 3], userPos[uIdx * 3 + 1], userPos[uIdx * 3 + 2],
        sensorPos[sIdx * 3], sensorPos[sIdx * 3 + 1], sensorPos[sIdx * 3 + 2],
      );
      colors.push(cLink.r, cLink.g, cLink.b, cLink.r, cLink.g, cLink.b);
    }
    if (positions.length === 0) return;

    const lineGeo = new THREE.BufferGeometry();
    lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    lineGeo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    const lineMat = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: 0.55,
      depthTest: false,
      blending: THREE.AdditiveBlending,
    });
    const assignmentLines = new THREE.LineSegments(lineGeo, lineMat);
    assignmentLines.renderOrder = 998; // under the point icons, above the core
    assignmentLines.visible = this.threeVisualMode() !== 'core';
    this.threeMeshGroup.add(assignmentLines);
    this.assignmentLines = assignmentLines;
  }

  private initThreeCyberTopology() {
    const host = this.threeCanvasRef?.nativeElement;
    if (!host) return;
    if (this.threeRenderer) {
      this.resizeThree();
      return;
    }

    try {
      const scene = new THREE.Scene();
      this.threeScene = scene;

      const rect = host.getBoundingClientRect();
      const w = Math.max(rect.width, 320);
      const h = Math.max(rect.height, 240);

      const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
      camera.position.set(0, 0, 8.5);
      this.threeCamera = camera;

      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.setSize(w, h, false);
      renderer.setClearColor(0x000000, 0);
      renderer.domElement.style.width = '100%';
      renderer.domElement.style.height = '100%';
      renderer.domElement.style.display = 'block';
      host.appendChild(renderer.domElement);
      this.threeRenderer = renderer;

      // WebGL contexts can be lost at any time (GPU driver reset, memory
      // pressure, or our own disposeThreeCyberTopology() calling
      // forceContextLoss() on navigation away from this page) - without
      // listening for it, the rAF loop below keeps calling render() on a
      // dead context forever (wasted CPU, frozen visual, never recovers).
      // preventDefault() is required for the browser to attempt automatic
      // restoration; only rebuild on restore, not on loss itself, so this
      // doesn't fight with the intentional forceContextLoss() cleanup path.
      renderer.domElement.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        if (this.threeAnimId) { cancelAnimationFrame(this.threeAnimId); this.threeAnimId = undefined; }
      }, false);
      renderer.domElement.addEventListener('webglcontextrestored', () => {
        this.disposeThreeCyberTopology();
        this.initThreeCyberTopology();
      }, false);

      // 0. Distant starfield backdrop — added to the scene, not the
      // rotating group, so it stays fixed behind everything for depth.
      // Purely atmospheric, not tied to any real data.
      const starCount = 240;
      const starPositions = new Float32Array(starCount * 3);
      for (let i = 0; i < starCount; i++) {
        const r = 6 + Math.random() * 6;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        starPositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
        starPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
        starPositions[i * 3 + 2] = r * Math.cos(phi);
      }
      const starGeo = new THREE.BufferGeometry();
      starGeo.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
      const starMat = new THREE.PointsMaterial({
        color: 0xffffff,
        size: 0.045,
        transparent: true,
        opacity: 0.55,
        sizeAttenuation: true,
      });
      scene.add(new THREE.Points(starGeo, starMat));

      const group = new THREE.Group();
      this.threeMeshGroup = group;
      group.rotation.set(0.25, 0, 0);
      scene.add(group);

      // 1. Inner glowing core node (Cyber Emerald reactor core)
      const coreGeo = new THREE.SphereGeometry(0.85, 16, 16);
      const coreMat = new THREE.MeshBasicMaterial({
        color: 0x10b981,
        wireframe: true,
        transparent: true,
        opacity: 0.55
      });
      const coreMesh = new THREE.Mesh(coreGeo, coreMat);
      group.add(coreMesh);
      this.coreMesh = coreMesh;

      // Soft ambient glow behind the core, always facing the camera.
      const coreGlowMat = new THREE.SpriteMaterial({
        map: this.makeGlowTexture(),
        color: 0x10b981,
        transparent: true,
        opacity: 0.5,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      });
      const coreGlow = new THREE.Sprite(coreGlowMat);
      coreGlow.scale.set(3.2, 3.2, 1);
      coreGlow.renderOrder = -1; // behind everything
      group.add(coreGlow);

      // 2. Orbiting perimeter rings (Royal Violet & Sky Cyan)
      const ring1Geo = new THREE.TorusGeometry(3.1, 0.025, 16, 80);
      const ring1Mat = new THREE.MeshBasicMaterial({ color: 0xa855f7, transparent: true, opacity: 0.5 });
      const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
      ring1.rotation.x = Math.PI / 2.3;
      group.add(ring1);
      this.ring1 = ring1;

      const ring2Geo = new THREE.TorusGeometry(3.4, 0.02, 16, 80);
      const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.4 });
      const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
      ring2.rotation.y = Math.PI / 3;
      ring2.rotation.x = Math.PI / 5;
      group.add(ring2);
      this.ring2 = ring2;

      // 3. Expanding shockwave ring (Electric Cyan pulse wave)
      const pRingGeo = new THREE.RingGeometry(0.8, 0.95, 36);
      const pRingMat = new THREE.MeshBasicMaterial({ color: 0x00f2fe, transparent: true, opacity: 0, side: THREE.DoubleSide });
      const pRing = new THREE.Mesh(pRingGeo, pRingMat);
      group.add(pRing);
      this.pulseRing = pRing;

      // 4. Orbital particle constellation — one real point per real user
      // (circle sprite, colored by role, matching the Identity & Seats
      // tier colors) plus one real point per real sensor (diamond sprite,
      // colored by online/offline, matching the Sensor Fleet Mesh dots).
      // Two distinct shapes so "which dot is a person vs. a sensor" is
      // readable at a glance, not just inferred from color. Positions are
      // still procedural — there's no real 3D coordinate for a user
      // account — but the count, shape and color are all real.
      const cAnalyst = new THREE.Color(0x00f2fe);
      const cSenior  = new THREE.Color(0xa855f7);
      const cViewer  = new THREE.Color(0x6366f1);
      const cOnline  = new THREE.Color(0x10b981);
      const cOffline = new THREE.Color(0xf59e0b);

      const realUsers = this.users();
      const realSensors = this.sensorKeys();

      const randomPoint = (): [number, number, number] => {
        const radius = 1.4 + Math.random() * 2.0;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        return [
          radius * Math.sin(phi) * Math.cos(theta),
          radius * Math.sin(phi) * Math.sin(theta),
          radius * Math.cos(phi),
        ];
      };

      const buildPoints = (
        count: number,
        colorFor: (i: number) => THREE.Color,
        texture: THREE.CanvasTexture,
      ): { points: THREE.Points; positions: Float32Array } => {
        const positions = new Float32Array(Math.max(count, 1) * 3);
        const colors = new Float32Array(Math.max(count, 1) * 3);
        for (let i = 0; i < count; i++) {
          const [x, y, z] = randomPoint();
          positions[i * 3] = x;
          positions[i * 3 + 1] = y;
          positions[i * 3 + 2] = z;
          const col = colorFor(i);
          colors[i * 3] = col.r;
          colors[i * 3 + 1] = col.g;
          colors[i * 3 + 2] = col.b;
        }
        const geo = new THREE.BufferGeometry();
        geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
        if (count === 0) geo.setDrawRange(0, 0);
        // Sized for a handful of real, individually-meaningful endpoints
        // (was 0.075, tuned for a 140-point decorative cloud) — each dot
        // needs to actually read as one real user/sensor, not blend into
        // haze. depthTest is off so a dot never gets visually swallowed by
        // the wireframe/core mesh behind it, and normal (not additive)
        // blending keeps cyan dots from washing out against the
        // similarly-colored cyan wireframe strands.
        const mat = new THREE.PointsMaterial({
          size: 0.75,
          map: texture,
          vertexColors: true,
          transparent: true,
          alphaTest: 0.3,
          opacity: 1,
          sizeAttenuation: true,
          depthTest: false,
          blending: THREE.NormalBlending,
        });
        return { points: new THREE.Points(geo, mat), positions };
      };

      const userBuild = buildPoints(
        realUsers.length,
        (i) => {
          const role = realUsers[i].role;
          return role === 'senior_analyst' ? cSenior : role === 'viewer' ? cViewer : cAnalyst;
        },
        this.makeDotTexture('person'),
      );
      const userPoints = userBuild.points;
      userPoints.renderOrder = 999; // always draw on top — depthTest is off above
      group.add(userPoints);
      this.points = userPoints;

      const sensorBuild = buildPoints(
        realSensors.length,
        (i) => (realSensors[i].active ? cOnline : cOffline),
        this.makeDotTexture('chip'),
      );
      const sensorPoints = sensorBuild.points;
      sensorPoints.renderOrder = 999;
      group.add(sensorPoints);
      this.sensorPoints = sensorPoints;

      // Stored so rebuildAssignmentLines() can redraw connections later
      // (e.g. after a sensor is assigned/unassigned) without moving any
      // dot or rebuilding the rest of the scene.
      this.meshUserPositions = userBuild.positions;
      this.meshSensorPositions = sensorBuild.positions;
      this.rebuildAssignmentLines();

      // Every real endpoint — every account and every sensor — gets a
      // spoke line into the inner core, so the mesh clearly reads as
      // "everything in this tenant connects to the platform core," not a
      // random cloud. Each spoke fades from the core's own emerald color
      // at the center to the endpoint's real role/status color at its tip,
      // so it looks like energy radiating outward, not a flat line.
      const cCoreGlow = new THREE.Color(0x10b981);
      const coreLinePositions: number[] = [];
      const coreLineColors: number[] = [];
      const spokeEndColors: THREE.Color[] = [];
      this.spokeEnds = [];
      const addCoreSpoke = (x: number, y: number, z: number, endColor: THREE.Color) => {
        coreLinePositions.push(0, 0, 0, x, y, z);
        coreLineColors.push(cCoreGlow.r, cCoreGlow.g, cCoreGlow.b, endColor.r, endColor.g, endColor.b);
        this.spokeEnds.push({ x, y, z, phase: Math.random() });
        spokeEndColors.push(endColor);
      };
      for (let i = 0; i < realUsers.length; i++) {
        const role = realUsers[i].role;
        const endColor = role === 'senior_analyst' ? cSenior : role === 'viewer' ? cViewer : cAnalyst;
        addCoreSpoke(userBuild.positions[i * 3], userBuild.positions[i * 3 + 1], userBuild.positions[i * 3 + 2], endColor);
      }
      for (let i = 0; i < realSensors.length; i++) {
        const endColor = realSensors[i].active ? cOnline : cOffline;
        addCoreSpoke(sensorBuild.positions[i * 3], sensorBuild.positions[i * 3 + 1], sensorBuild.positions[i * 3 + 2], endColor);
      }
      if (coreLinePositions.length > 0) {
        const coreLineGeo = new THREE.BufferGeometry();
        coreLineGeo.setAttribute('position', new THREE.Float32BufferAttribute(coreLinePositions, 3));
        coreLineGeo.setAttribute('color', new THREE.Float32BufferAttribute(coreLineColors, 3));
        const coreLineMat = new THREE.LineBasicMaterial({
          vertexColors: true,
          transparent: true,
          opacity: 0.6,
          depthTest: false,
          blending: THREE.AdditiveBlending,
        });
        const coreLines = new THREE.LineSegments(coreLineGeo, coreLineMat);
        coreLines.renderOrder = 997; // under the assignment lines and icons
        group.add(coreLines);
        this.coreLines = coreLines;
      }

      // Traveling energy pulses — one per spoke, animated outward from the
      // core to its endpoint and looping, so the hub-and-spoke connection
      // reads as active data flow, not a static diagram. Purely decorative
      // motion — the underlying spoke count/colors above are the real part.
      if (this.spokeEnds.length > 0) {
        const energyGeo = new THREE.BufferGeometry();
        const energyPositions = new Float32Array(this.spokeEnds.length * 3);
        const energyColors = new Float32Array(this.spokeEnds.length * 3);
        spokeEndColors.forEach((col, i) => {
          energyColors[i * 3] = col.r;
          energyColors[i * 3 + 1] = col.g;
          energyColors[i * 3 + 2] = col.b;
        });
        energyGeo.setAttribute('position', new THREE.BufferAttribute(energyPositions, 3));
        energyGeo.setAttribute('color', new THREE.BufferAttribute(energyColors, 3));
        const energyMat = new THREE.PointsMaterial({
          size: 0.16,
          map: this.makeGlowTexture(),
          vertexColors: true,
          transparent: true,
          opacity: 1,
          depthTest: false,
          sizeAttenuation: true,
          blending: THREE.AdditiveBlending,
        });
        const energyPoints = new THREE.Points(energyGeo, energyMat);
        energyPoints.renderOrder = 996;
        group.add(energyPoints);
        this.energyPoints = energyPoints;
      }

      // Snapshot so hover-picking indices always line up with what was
      // actually drawn, even if this.users()/this.sensorKeys() change later.
      this.meshUsersSnapshot = realUsers;
      this.meshSensorsSnapshot = realSensors;
      this.raycaster.params.Points = { threshold: 0.2 };

      // Interactive mouse orbit
      const onPointerDown = (e: MouseEvent | TouchEvent) => {
        this.isPointerDown = true;
        const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
        const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
        this.prevPointerX = clientX;
        this.prevPointerY = clientY;
      };
      const onPointerMove = (e: MouseEvent | TouchEvent) => {
        if (!this.isPointerDown || !this.threeMeshGroup) return;
        const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
        const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
        const dx = clientX - this.prevPointerX;
        const dy = clientY - this.prevPointerY;
        this.threeMeshGroup.rotation.y += dx * 0.008;
        this.threeMeshGroup.rotation.x += dy * 0.008;
        this.prevPointerX = clientX;
        this.prevPointerY = clientY;
      };
      const onPointerUp = () => { this.isPointerDown = false; };

      // Scroll to zoom in/out, clamped so you can't clip through the mesh
      // or zoom out to nothing.
      const onWheel = (e: WheelEvent) => {
        e.preventDefault();
        camera.position.z = Math.min(14, Math.max(3.5, camera.position.z + e.deltaY * 0.01));
      };

      // Hover a real user/sensor dot to see its real identity + IP.
      // Skipped while dragging to orbit, since that's a different gesture.
      const onHoverMove = (e: MouseEvent) => {
        if (this.isPointerDown || !this.points || !this.sensorPoints) {
          this.hoveredNode.set(null);
          return;
        }
        const r = host.getBoundingClientRect();
        this.mouseNdc.x = ((e.clientX - r.left) / r.width) * 2 - 1;
        this.mouseNdc.y = -((e.clientY - r.top) / r.height) * 2 + 1;
        this.raycaster.setFromCamera(this.mouseNdc, camera);
        const hits = this.raycaster.intersectObjects([this.points, this.sensorPoints], false);
        const hit = hits[0];
        if (!hit || hit.index === undefined) {
          this.hoveredNode.set(null);
          return;
        }
        if (hit.object === this.points) {
          const u = this.meshUsersSnapshot[hit.index];
          if (u) {
            this.hoveredNode.set({
              type: 'user',
              name: u.username,
              sub: this.getRoleLabel(u.role),
              ip: this.userSessionIps()[u.username] || 'No active session',
            });
          }
        } else {
          const s = this.meshSensorsSnapshot[hit.index];
          if (s) {
            this.hoveredNode.set({
              type: 'sensor',
              name: s.name || s.key_prefix,
              sub: s.active ? 'Online' : 'Offline',
              ip: this.sensorIps()[s.key_prefix] || 'No traffic seen yet',
            });
          }
        }
        this.hoverTooltipPos.set({ x: e.clientX, y: e.clientY });
      };
      host.addEventListener('mousemove', onHoverMove);
      host.addEventListener('mouseleave', () => this.hoveredNode.set(null));

      host.addEventListener('mousedown', onPointerDown as any);
      window.addEventListener('mousemove', onPointerMove as any);
      window.addEventListener('mouseup', onPointerUp);
      host.addEventListener('touchstart', onPointerDown as any, { passive: true });
      window.addEventListener('touchmove', onPointerMove as any, { passive: true });
      window.addEventListener('touchend', onPointerUp);
      host.addEventListener('wheel', onWheel, { passive: false });
      host.addEventListener('click', () => this.triggerPulseWave());

      // Resize observer
      const resize = () => { this.resizeThree(); };
      this.threeResizeObs = new ResizeObserver(resize);
      this.threeResizeObs.observe(host);

      // Animation loop
      let clock = 0;
      const animate = () => {
        this.threeAnimId = requestAnimationFrame(animate);
        const spd = this.threeSpeed();
        clock += 0.015 * spd;
        if (!this.isPointerDown && this.threeMeshGroup) {
          this.threeMeshGroup.rotation.y += 0.005 * spd;
          this.threeMeshGroup.rotation.x += 0.0015 * spd;
        }
        ring1.rotation.z += 0.004 * spd;
        ring2.rotation.z -= 0.006 * spd;
        const scale = 1 + Math.sin(clock * 2) * 0.04;
        coreMesh.scale.set(scale, scale, scale);
        // Core spokes breathe in sync with the core itself — reads as
        // energy actively radiating out to every endpoint, not a static line.
        if (this.coreLines) {
          (this.coreLines.material as THREE.LineBasicMaterial).opacity = 0.5 + Math.sin(clock * 2) * 0.15;
        }
        if (this.energyPoints && this.spokeEnds.length) {
          const posAttr = this.energyPoints.geometry.attributes['position'] as THREE.BufferAttribute;
          for (let i = 0; i < this.spokeEnds.length; i++) {
            const s = this.spokeEnds[i];
            const t = (clock * 0.12 + s.phase) % 1;
            posAttr.setXYZ(i, s.x * t, s.y * t, s.z * t);
          }
          posAttr.needsUpdate = true;
        }

        if (this.pulseOpacity > 0 && this.pulseRing) {
          this.pulseScale += 0.08 * spd;
          this.pulseOpacity -= 0.015 * spd;
          this.pulseRing.scale.set(this.pulseScale, this.pulseScale, this.pulseScale);
          (this.pulseRing.material as THREE.MeshBasicMaterial).opacity = Math.max(0, this.pulseOpacity);
        }

        renderer.render(scene, camera);
      };
      animate();
    } catch (e) {
      console.warn('Three.js Cyber Topology initialization warning:', e);
    }
  }

  private resizeThree() {
    const host = this.threeCanvasRef?.nativeElement;
    if (!host || !this.threeCamera || !this.threeRenderer) return;
    const rect = host.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    this.threeCamera.aspect = rect.width / rect.height;
    this.threeCamera.updateProjectionMatrix();
    this.threeRenderer.setSize(rect.width, rect.height, false);
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get usernameError() { return this.validateUsername(this.userForm.username); }

  get usernameFeedback() {
    const status = this.usernameStatus();
    if (this.editingUser() || this.usernameError) return '';
    if (status === 'checking')    return 'Checking username availability...';
    if (status === 'available')   return 'Username is available';
    if (status === 'taken')       return 'Username already exists';
    if (status === 'unavailable') return 'Could not check username availability';
    return '';
  }

  get usernameFeedbackType(): 'neutral' | 'success' | 'error' {
    const status = this.usernameStatus();
    if (status === 'available') return 'success';
    if (status === 'taken' || status === 'unavailable') return 'error';
    return 'neutral';
  }

  get passwordErrors() {
    return this.validatePassword(this.userForm.password, this.userForm.username, !this.editingUser());
  }

  passwordStrength(): number {
    const p = this.userForm.password || '';
    let score = 0;
    if (p.length >= 8) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[!@#$%^&*()\-_=+\[\]{}|;':",.\/<>?]/.test(p)) score++;
    return score;
  }

  passwordStrengthLabel(): string { return (['', 'Weak', 'Fair', 'Good', 'Strong'])[this.passwordStrength()] || ''; }
  passwordStrengthColor(): string { return (['', '#ef4444', '#f59e0b', '#3b82f6', '#22c55e'])[this.passwordStrength()] || ''; }

  get canSaveUser() {
    return (
      !this.saving() && !this.usernameError &&
      this.passwordErrors.length === 0 &&
      (this.editingUser() || this.usernameStatus() === 'available')
    );
  }

  // ── Users ─────────────────────────────────────────────────────────────────

  loadUsers() {
    this.loading.set(true);
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.permLabelsCache.clear();
        const tid = this.tenantId;
        this.users.set(
          (data.users || [])
            .filter((u: TenantUser) => u.tenant_id === tid)
            .filter((u: TenantUser) => this.isManageableTenantUser(u))
            .map((u: TenantUser) => ({
              ...u,
              active: u.active !== false,
              permissions: this.normalizePermissions(u.permissions, u.role),
              // ClickHouse sends "YYYY-MM-DD HH:mm:ss" with no timezone —
              // browsers parse that as LOCAL time, silently shifting every
              // timestamp by the viewer's UTC offset. Normalize to real UTC
              // once here so the growth chart, table, and CSV export all
              // agree with the server.
              created_at: this.toUtcIsoString(u.created_at),
            }))
        );
        this.updateCharts();
        this.seedLiveAuditFeed();
        this.loading.set(false);
        this.usersLoaded = true;
        this.maybeInitTopology();
      },
      error: () => {
        this.loading.set(false);
        this.showMessage('Failed to load tenant users', 'error');
        this.usersLoaded = true;
        this.maybeInitTopology();
      },
    });
  }

  // ── Sensor assignment ─────────────────────────────────────────────────────

  loadSensorData() {
    this.sensorAssignLoading.set(true);

    // Sensor keys come from the shared TenantStatusService poll (see the
    // effect() wired up in the constructor) rather than a call here - this
    // used to fetch getSensorKeys() independently, in parallel with that
    // same shared poll's own identical call, on every page load.
    this.tenantStatus.startPolling();

    this.api.getSensorAssignments().subscribe({
      next: (res) => {
        this.sensorAssignments.set(res.assignments || []);
        this.sensorAssignLoading.set(false);
        this.assignmentsLoaded = true;
        this.maybeInitTopology();
      },
      error: () => {
        this.sensorAssignLoading.set(false);
        this.assignmentsLoaded = true;
        this.maybeInitTopology();
      }
    });
  }

  getUserSensorIds(userId: string): string[] {
    return this.sensorAssignments().filter(a => a.user_id === userId).map(a => a.sensor_id);
  }

  getSensorLabel(prefix: string): string {
    const s = this.sensorKeys().find(k => k.key_prefix === prefix);
    return s ? (s.name || s.key_prefix) : prefix;
  }

  getAvailableSensors(userId: string): SensorKey[] {
    const assigned = new Set(this.getUserSensorIds(userId));
    return this.sensorKeys().filter(k => !assigned.has(k.key_prefix));
  }

  private addDocClickListener() {
    if (this.docClickListener) return; // already attached
    this.docClickListener = () => {
      const open = this.sensorDropdownOpen();
      if (Object.keys(open).some(k => open[k])) this.sensorDropdownOpen.set({});
      this.removeDocClickListener();
    };
    document.addEventListener('click', this.docClickListener);
  }

  private removeDocClickListener() {
    if (this.docClickListener) {
      document.removeEventListener('click', this.docClickListener);
      this.docClickListener = null;
    }
  }

  toggleSensorDropdown(userId: string, event: Event) {
    event.stopPropagation();
    const wasOpen = !!this.sensorDropdownOpen()[userId];
    if (wasOpen) {
      this.sensorDropdownOpen.set({});
      this.removeDocClickListener();
    } else {
      this.sensorDropdownOpen.set({ [userId]: true });
      this.addDocClickListener();
    }
  }

  isSensorSelected(userId: string, sensorId: string): boolean {
    return (this.pendingSensorSel()[userId] || []).includes(sensorId);
  }

  toggleSensorSelection(userId: string, sensorId: string) {
    this.pendingSensorSel.update(sel => {
      const current = sel[userId] || [];
      return {
        ...sel,
        [userId]: current.includes(sensorId)
          ? current.filter(id => id !== sensorId)
          : [...current, sensorId]
      };
    });
  }

  getSelectedCount(userId: string): number {
    return (this.pendingSensorSel()[userId] || []).length;
  }

  addSensorsToUser(userId: string) {
    const toAssign = [...(this.pendingSensorSel()[userId] || [])];
    if (toAssign.length === 0) return;

    this.sensorAssignSaving.set(true);
    this.sensorDropdownOpen.set({});
    const total = toAssign.length;
    let done = 0, errors = 0;

    for (const sensorId of toAssign) {
      this.api.assignSensor(userId, sensorId).subscribe({
        next: () => {
          this.sensorAssignments.update(s => [...s, { user_id: userId, sensor_id: sensorId }]);
          done++;
          if (done + errors === total) {
            this.pendingSensorSel.update(s => ({ ...s, [userId]: [] }));
            this.sensorAssignSaving.set(false);
            this.showMessage(
              errors === 0
                ? `${total} sensor(s) assigned. Analyst must re-login for changes to take effect.`
                : `${total - errors} assigned, ${errors} failed.`,
              errors === 0 ? 'success' : 'error'
            );
            if (errors === 0) {
              const username = this.users().find(u => u.id === userId)?.username || userId;
              this.pushLiveEvent('sensor', 'Sensor Access Granted', `${username} · ${total} sensor(s)`, 'SYNCED', 'badge-sync');
            }
            this.rebuildAssignmentLines();
          }
        },
        error: () => {
          errors++;
          if (done + errors === total) {
            this.pendingSensorSel.update(s => ({ ...s, [userId]: [] }));
            this.sensorAssignSaving.set(false);
            this.showMessage(`${total - errors} assigned, ${errors} failed.`, 'error');
          }
        }
      });
    }
  }

  removeSensorFromUser(userId: string, sensorId: string) {
    this.sensorAssignSaving.set(true);
    this.api.unassignSensor(userId, sensorId).subscribe({
      next: () => {
        this.sensorAssignments.update(s =>
          s.filter(a => !(a.user_id === userId && a.sensor_id === sensorId))
        );
        this.sensorAssignSaving.set(false);
        this.showMessage('Sensor removed. Analyst must log out and back in.', 'success');
        const username = this.users().find(u => u.id === userId)?.username || userId;
        this.pushLiveEvent('sensor', 'Sensor Access Revoked', username, 'REMOVED', 'badge-stable');
        this.rebuildAssignmentLines();
      },
      error: () => {
        this.sensorAssignSaving.set(false);
        this.showMessage('Failed to remove sensor assignment', 'error');
      }
    });
  }

  // ── User form ─────────────────────────────────────────────────────────────

  openCreateForm() {
    this.clearUsernameCheck();
    this.usernameTouched.set(false);
    this.passwordTouched.set(false);
    this.editingUser.set(null);
    this.userForm = {
      username: '', password: '', role: 'analyst', active: true,
      permissions: this.defaultPermissionsFor('analyst'),
    };
    this.showForm.set(true);
  }

  openEditForm(user: TenantUser) {
    this.clearUsernameCheck();
    this.usernameTouched.set(false);
    this.passwordTouched.set(false);
    this.editingUser.set(user);
    this.userForm = {
      username: user.username, password: '', role: user.role,
      active: user.active !== false,
      permissions: this.normalizePermissions(user.permissions, user.role),
    };
    this.showForm.set(true);
  }

  closeForm() {
    this.clearUsernameCheck();
    this.showForm.set(false);
  }

  onUsernameChange() {
    this.clearUsernameCheck();
    if (this.editingUser() || this.usernameError) { this.usernameStatus.set('idle'); return; }
    const username = this.userForm.username.trim();
    this.usernameStatus.set('checking');
    this.usernameTimer = setTimeout(() => {
      this.usernameCheckSub = this.auth.checkUsername(username).subscribe({
        next: (res) => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus.set(res.exists ? 'taken' : 'available');
        },
        error: () => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus.set('unavailable');
        },
      });
    }, 400);
  }

  saveUser() {
    const validationError = this.firstValidationError();
    if (validationError) { this.showMessage(validationError, 'error'); return; }

    const editing = this.editingUser();
    if (editing) {
      this.saving.set(true);
      const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
      const userId      = editing.id;
      const wasActive   = editing.active !== false;
      const nowActive   = this.userForm.active;
      const statusChanged = wasActive !== nowActive;

      this.api.updateUserPermissions(userId, permissions).subscribe({
        next: (data: any) => {
          if (data.status !== 'ok') {
            this.saving.set(false);
            this.showMessage(data.message || 'Failed to update user access', 'error');
            return;
          }

          const afterPermissions = () => {
            if (statusChanged) {
              this.api.setUserStatus(userId, nowActive).subscribe({
                next: (sd: any) => {
                  if (sd.status === 'ok') {
                    this.afterSaveComplete(userId, permissions, nowActive);
                  } else {
                    this.saving.set(false);
                    this.showMessage(sd.message || 'Permissions saved but failed to update status', 'error');
                  }
                },
                error: () => {
                  this.saving.set(false);
                  this.showMessage('Permissions saved but failed to update status', 'error');
                }
              });
            } else {
              this.afterSaveComplete(userId, permissions, nowActive);
            }
          };

          if (this.userForm.password.trim()) {
            this.api.resetUserPassword(userId, this.userForm.password).subscribe({
              next: (pd: any) => {
                if (pd.status === 'ok') { afterPermissions(); }
                else {
                  this.saving.set(false);
                  this.showMessage(pd.message || 'Access updated, but failed to reset password', 'error');
                }
              },
              error: () => {
                this.saving.set(false);
                this.showMessage('Access updated, but failed to reset password', 'error');
              }
            });
          } else {
            afterPermissions();
          }
        },
        error: () => {
          this.saving.set(false);
          this.showMessage('Failed to update user access', 'error');
        },
      });
      return;
    }

    this.saving.set(true);
    const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
    this.api.createUser({
      username: this.userForm.username.trim(),
      password: this.userForm.password,
      role: this.userForm.role,
      tenant_id: this.tenantId,
      permissions,
    }).subscribe({
      next: (data: any) => {
        this.saving.set(false);
        if (data.status === 'ok') {
          const username = this.userForm.username.trim();
          const role = this.userForm.role;
          this.closeForm();
          this.showMessage('User created for this tenant', 'success');
          this.pushLiveEvent('auth', 'Account Created', `${username} · ${this.getRoleLabel(role)}`, 'CREATED', 'badge-valid');
          this.loadUsers();
        } else {
          this.showMessage(data.message || 'Failed to create user', 'error');
        }
      },
      error: () => { this.saving.set(false); this.showMessage('Failed to create user', 'error'); },
    });
  }

  private afterSaveComplete(userId: string, permissions: string[], active: boolean) {
    this.saving.set(false);
    const username = this.users().find(u => u.id === userId)?.username || userId;
    this.users.update(list => list.map(u => u.id === userId ? { ...u, permissions, active } : u));
    this.updateCharts();
    this.closeForm();
    this.showMessage(active ? 'User updated successfully' : 'User disabled successfully', 'success');
    this.pushLiveEvent(
      'policy',
      active ? 'Account Access Updated' : 'Account Disabled',
      username,
      active ? 'UPDATED' : 'DISABLED',
      active ? 'badge-priv' : 'badge-stable'
    );
  }

  deleteUser(user: TenantUser) {
    if (!confirm(`Delete user "${user.username}" from this tenant?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.users.update(list => list.filter(u => u.id !== user.id));
        this.showMessage('User deleted', 'success');
        this.pushLiveEvent('auth', 'Account Deleted', user.username, 'REMOVED', 'badge-stable');
      },
      error: () => this.showMessage('Failed to delete user', 'error'),
    });
  }

  togglePermission(permission: string) {
    const selected = new Set(this.userForm.permissions);
    if (selected.has(permission)) selected.delete(permission); else selected.add(permission);
    this.userForm.permissions = Array.from(selected);
  }

  hasPermission(permission: string) { return this.userForm.permissions.includes(permission); }

  onRoleChange() {
    if (!this.editingUser()) this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role);
  }

  selectRole(value: string) {
    if (this.editingUser()) return;
    this.userForm.role = value;
    this.onRoleChange();
  }

  getUserStatus(user: TenantUser): 'active' | 'disabled' { return user.active !== false ? 'active' : 'disabled'; }
  getRoleLabel(role: string) { return this.roleOptions.find(o => o.value === role)?.label || role; }

  getPermissionLabels(user: TenantUser): string[] {
    const hit = this.permLabelsCache.get(user.id);
    if (hit) return hit;
    const permissions = this.normalizePermissions(user.permissions, user.role);
    const labels = this.permissionOptions.filter(o => permissions.includes(o.key)).map(o => o.label);
    this.permLabelsCache.set(user.id, labels);
    return labels;
  }

  toggleSort(field: keyof TenantUser | 'status') {
    if (this.sortField() === field) this.sortAscending.update(v => !v);
    else { this.sortField.set(field); this.sortAscending.set(true); }
  }

  toggleSelection(userId: string) {
    this.selectedUserIds.update(s => {
      const next = new Set(s);
      if (next.has(userId)) next.delete(userId); else next.add(userId);
      return next;
    });
  }

  toggleAll() {
    const visible = this.filteredAndSortedUsers();
    this.selectedUserIds.update(s => {
      if (visible.length > 0 && visible.every(u => s.has(u.id))) return new Set<string>();
      return new Set(visible.map(u => u.id));
    });
  }

  isAllSelected(): boolean {
    const visible = this.filteredAndSortedUsers();
    return visible.length > 0 && visible.every(u => this.selectedUserIds().has(u.id));
  }

  bulkUpdateStatus(active: boolean) {
    const ids = this.selectedUserIds();
    if (ids.size === 0) return;
    const action = active ? 'enable' : 'disable';
    if (!confirm(`Are you sure you want to ${action} ${ids.size} users?`)) return;

    let completed = 0;
    const total = ids.size;
    this.saving.set(true);

    ids.forEach(id => {
      this.api.setUserStatus(id, active).subscribe({
        next: () => {
          completed++;
          if (completed === total) {
            this.selectedUserIds.set(new Set());
            this.saving.set(false);
            this.showMessage(`Successfully ${action}d ${total} users`, 'success');
            this.loadUsers();
          }
        },
        error: () => {
          completed++;
          if (completed === total) { this.saving.set(false); this.loadUsers(); }
        }
      });
    });
  }

  exportToCSV() {
    const data = this.filteredAndSortedUsers().map(u => ({
      Username: u.username,
      Role: this.getRoleLabel(u.role),
      Status: u.active ? 'Active' : 'Disabled',
      Created: u.created_at ? new Date(u.created_at).toLocaleString() : 'Unknown',
      Permissions: this.normalizePermissions(u.permissions, u.role).join('; ')
    }));
    if (data.length === 0) { this.showMessage('No users to export', 'error'); return; }
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(row => headers.map(h => `"${(row as any)[h]}"`).join(','))].join('\n');
    const blob      = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const objectUrl = URL.createObjectURL(blob);
    const link      = document.createElement('a');
    link.setAttribute('href', objectUrl);
    link.setAttribute('download', `tenant_users_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(objectUrl);
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    if (this.messageTimer) clearTimeout(this.messageTimer);
    this.messageTimer = setTimeout(() => { this.message.set(''); this.messageTimer = null; }, 5000);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private updateCharts() {
    const list     = this.users();
    const analyst  = list.filter(u => u.role === 'analyst').length;
    const senior   = list.filter(u => u.role === 'senior_analyst').length;
    const viewer   = list.filter(u => u.role === 'viewer').length;

    this.roleChartData.set({
      labels: ['Analyst', 'Senior Analyst', 'Viewer'],
      datasets: [{
        data: [analyst, senior, viewer],
        backgroundColor: ['#00f2fe', '#a855f7', '#6366f1'],
        hoverBackgroundColor: ['#38bdf8', '#c084fc', '#818cf8'],
        borderWidth: 4,
        borderColor: '#171b37',
        hoverOffset: 6
      }]
    });

    const active   = this.activeUsers();
    const disabled = list.length - active;
    this.statusChartData.set({
      labels: ['Active', 'Disabled'],
      datasets: [{
        data: [active, disabled],
        backgroundColor: ['#10b981', '#1e2640'],
        hoverBackgroundColor: ['#34d399', '#2e3859'],
        borderWidth: 4,
        borderColor: '#171b37',
        hoverOffset: 6
      }]
    });

    // Real account-growth timeline — buckets actual created_at timestamps.
    // No fabricated "auth velocity"/"policy clearance" event history exists,
    // so this shows what we can genuinely measure: when accounts were made.
    const tf = this.authTimeframe();
    const bucketPlan: Record<string, { count: number; stepMs: number; unit: 'h' | 'd' }> = {
      '6h':  { count: 6,  stepMs: 3_600_000,      unit: 'h' },
      '12h': { count: 6,  stepMs: 2 * 3_600_000,  unit: 'h' },
      '24h': { count: 12, stepMs: 2 * 3_600_000,  unit: 'h' },
      '7d':  { count: 7,  stepMs: 24 * 3_600_000, unit: 'd' },
    };
    const plan = bucketPlan[tf] || bucketPlan['24h'];
    const counts = this.bucketByCreatedAt(list, plan.count, plan.stepMs);
    const unitMs = plan.unit === 'd' ? 86_400_000 : 3_600_000;
    const labels = Array.from({ length: plan.count }, (_, i) => {
      const stepsAgo = (plan.count - 1 - i) * (plan.stepMs / unitMs);
      return stepsAgo === 0 ? (plan.unit === 'd' ? 'Today' : 'Now') : `-${stepsAgo}${plan.unit}`;
    });

    this.authTimelineChartData.set({
      labels,
      datasets: [
        {
          label: 'Accounts Created',
          data: counts,
          borderColor: '#00f2fe',
          backgroundColor: 'transparent',
          fill: false,
          pointBackgroundColor: '#00f2fe',
          pointBorderColor: '#171b37',
          pointBorderWidth: 2
        }
      ]
    });

    // Real per-category access counts — from each user's actual permissions[],
    // grouped by the same licensed categories used in the permission editor.
    const categories = this.permissionCategories();
    const hasAnyOf = (u: TenantUser, keys: Set<string>) => {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      return perms.some(p => keys.has(p));
    };
    this.clearanceBarChartData.set({
      labels: categories.map(c => c.title),
      datasets: [
        {
          label: 'Analyst Tier',
          data: categories.map(c => {
            const keys = new Set(c.options.map(o => o.key));
            return list.filter(u => u.role === 'analyst' && hasAnyOf(u, keys)).length;
          }),
          backgroundColor: '#06b6d4',
          borderRadius: 6
        },
        {
          label: 'Senior Analyst Tier',
          data: categories.map(c => {
            const keys = new Set(c.options.map(o => o.key));
            return list.filter(u => u.role === 'senior_analyst' && hasAnyOf(u, keys)).length;
          }),
          backgroundColor: '#8b5cf6',
          borderRadius: 6
        }
      ]
    });
  }

  private formatRelativeTime(ts: number): string {
    const diffMs = Date.now() - ts;
    if (diffMs < 60000) return 'Just now';
    const mins = Math.floor(diffMs / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  /** Seeds the Live Access Stream with real history instead of leaving it
   *  empty until something happens this session: real account-creation
   *  timestamps (already loaded) plus real active sessions (with real
   *  login time, IP, device from Redis). Anything pushLiveEvent() adds
   *  later is simply prepended on top of this. */
  private seedLiveAuditFeed() {
    const events: any[] = [];
    for (const u of this.users()) {
      if (!u.created_at) continue;
      const ts = new Date(u.created_at).getTime();
      if (Number.isNaN(ts)) continue;
      events.push({
        id: `created-${u.id}`,
        type: 'auth',
        title: 'Account Created',
        subtitle: `${u.username} · ${this.getRoleLabel(u.role)}`,
        badge: 'CREATED',
        badgeClass: 'badge-valid',
        time: this.formatRelativeTime(ts),
        ts,
      });
    }
    // Single real call, reused for both the feed seed above and the mesh
    // hover-tooltip IPs (loadUserSessionIps() used to call this
    // separately — merged to stop firing /api/admin/active-sessions twice
    // on every load).
    this.api.getActiveSessions().subscribe({
      next: (data: any) => {
        const sessions: any[] = data?.sessions || [];
        const ipMap: Record<string, string> = {};
        for (const s of sessions) {
          if (s.username && s.ip) ipMap[s.username] = s.ip;
          const ts = (Number(s.login_time) || 0) * 1000;
          events.push({
            id: `session-${s.jti}`,
            type: 'auth',
            title: 'Session Active',
            subtitle: `${s.username}${s.ip ? ' · ' + s.ip : ''}${s.device ? ' · ' + s.device : ''}`,
            badge: 'ACTIVE',
            badgeClass: 'badge-sync',
            time: ts ? this.formatRelativeTime(ts) : 'Just now',
            ts: ts || Date.now(),
          });
        }
        this.userSessionIps.set(ipMap);
        events.sort((a, b) => b.ts - a.ts);
        this.liveAuditEvents.set(events.slice(0, 10));
      },
      error: () => {
        events.sort((a, b) => b.ts - a.ts);
        this.liveAuditEvents.set(events.slice(0, 10));
      },
    });
  }

  /** Normalizes a ClickHouse "YYYY-MM-DD HH:mm:ss" (implicitly UTC, no
   *  offset) timestamp to a real UTC ISO string, so `new Date(...)` and the
   *  Angular `date` pipe parse it correctly regardless of the viewer's
   *  timezone — otherwise it's silently read as local time. */
  private toUtcIsoString(value?: string): string | undefined {
    if (!value) return value;
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    return /Z$|[+-]\d{2}:\d{2}$/.test(normalized) ? normalized : `${normalized}Z`;
  }

  /** Counts real user.created_at timestamps into `numBuckets` trailing windows of `stepMs`, most-recent bucket last. */
  private bucketByCreatedAt(list: TenantUser[], numBuckets: number, stepMs: number): number[] {
    const now = Date.now();
    const start = now - numBuckets * stepMs;
    const counts = new Array(numBuckets).fill(0);
    for (const u of list) {
      if (!u.created_at) continue;
      const t = new Date(u.created_at).getTime();
      if (Number.isNaN(t) || t < start || t > now) continue;
      const idx = Math.min(numBuckets - 1, Math.max(0, Math.floor((t - start) / stepMs)));
      counts[idx]++;
    }
    return counts;
  }

  // ── License-aware permission helpers ──────────────────────────────────────

  readonly licensedPermissionOptions = computed(() =>
    this.permissionCategories().flatMap(c => c.options)
  );

  readonly licensedPermissionCategories = computed(() =>
    this.permissionCategories()
  );

  readonly visibleEnabledCount = computed(() => {
    const licensed = new Set(this.licensedPermissionOptions().map(p => p.key));
    return this.userForm.permissions.filter(p => licensed.has(p)).length;
  });

  private defaultPermissionsFor(role: string): string[] {
    const licensed = this.licensedPermissionOptions().map(p => p.key);
    if (role === 'viewer')         return ['dashboard', 'health'].filter(k => licensed.includes(k));
    if (role === 'senior_analyst') return licensed;
    // analyst: dashboard + everything except enforce pages (honeypots/retrospective)
    const enforce = new Set(['honeypots', 'retrospective']);
    return licensed.filter(k => !enforce.has(k));
  }

  private normalizePermissions(value: unknown, role: string): string[] {
    const permissions = Array.isArray(value)
      ? value
      : typeof value === 'string' ? value.split(',') : this.defaultPermissionsFor(role);
    return Array.from(new Set(
      permissions.map(p => String(p).trim()).filter(Boolean)
        .map(p => p.endsWith(':view') ? p.replace(':view', '') : p)
        .map(p => p === 'network' ? 'network-map' : p)
    ));
  }

  private isManageableTenantUser(user: TenantUser) {
    if (['admin', 'super_admin', 'tenant_admin'].includes(user.role)) return false;
    const me = this.auth.getUser();
    return user.id !== me?.id && user.username !== me?.username;
  }

  private firstValidationError() {
    const status = this.usernameStatus();
    if (this.usernameError) return this.usernameError;
    if (!this.editingUser() && status === 'checking')    return 'Wait for username availability check';
    if (!this.editingUser() && status === 'taken')       return 'Username already exists';
    if (!this.editingUser() && status === 'unavailable') return 'Could not check username availability';
    if (!this.editingUser() && status !== 'available')   return 'Confirm username availability';
    return this.passwordErrors[0] || '';
  }

  private validateUsername(username: string) {
    const value = username.trim();
    if (!value) return 'Username is required';
    if (value.length < 3) return 'Username must be at least 3 characters';
    if (value.length > 50) return 'Username must be 50 characters or less';
    if (!this.usernamePattern.test(value)) return 'Username can use letters, numbers, dot, underscore, and hyphen only';
    if (!this.editingUser() && this.users().some(u => u.username?.trim().toLowerCase() === value.toLowerCase())) return 'Username already exists';
    return '';
  }

  private validatePassword(password: string, username: string, required: boolean) {
    const value = password || '';
    const errors: string[] = [];
    if (!value) { if (required) errors.push('Password is required'); return errors; }
    if (value.length < 8)            errors.push('Password must be at least 8 characters');
    if (!/[A-Z]/.test(value))        errors.push('Password needs an uppercase letter');
    if (!/[a-z]/.test(value))        errors.push('Password needs a lowercase letter');
    if (!/[0-9]/.test(value))        errors.push('Password needs a number');
    if (!/[^A-Za-z0-9]/.test(value)) errors.push('Password needs a special character');
    if (username.trim() && value.toLowerCase() === username.trim().toLowerCase()) errors.push('Password cannot be the same as username');
    return errors;
  }

  private clearUsernameCheck() {
    if (this.usernameTimer) { clearTimeout(this.usernameTimer); this.usernameTimer = null; }
    this.usernameCheckSub?.unsubscribe();
    this.usernameCheckSub = null;
    this.usernameStatus.set('idle');
  }
}
