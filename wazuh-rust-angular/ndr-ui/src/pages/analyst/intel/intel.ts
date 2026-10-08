import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { Notifications, ThreatNotification } from '../../../services/notifications/notifications';
import { Subscription } from 'rxjs';
import {
  LucideAngularModule,
  Search, ShieldCheck, CircleAlert, RefreshCw, Hash, Bell, Plus,
  Trash2, Globe, Database, Layers, Download, X,
  Map as LucideMap,
  CheckCircle2, AlertTriangle, Activity, TrendingUp, ExternalLink,
  Filter, ChevronUp, ChevronDown, Eye, Cpu, FileWarning
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';

type Tab = 'overview' | 'ioc-tools' | 'watchlist' | 'feeds' | 'geo';

@Component({
  selector: 'app-intel',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './intel.html',
  styleUrl: './intel.css'
})
export class Intel implements OnInit, OnDestroy {

  // ── Feed stats ────────────────────────────────────────────────────────────
  totalMaliciousIps     = 0;
  totalMaliciousHashes  = 0;
  totalMaliciousDomains = 0;
  source       = '';
  lastRefresh  = '';
  feedSources: any[] = [];
  loading      = true;

  // ── Detected in network ───────────────────────────────────────────────────
  detectedInNetwork: any[] = [];
  filterText = '';
  sortField  = 'hits';
  sortDir: 'asc' | 'desc' = 'desc';

  // ── Tabs ─────────────────────────────────────────────────────────────────
  activeTab: Tab = 'overview';

  // ── Live alerts ───────────────────────────────────────────────────────────
  liveAlerts: ThreatNotification[] = [];
  newAlertCount = 0;

  // ── IOC Lookup ────────────────────────────────────────────────────────────
  searching    = false;
  searchQuery  = '';
  lookupResult: any = null;

  // ── Add Manual IOC ────────────────────────────────────────────────────────
  addIocType           = 'ip';
  addIocValue          = '';
  addIocAttackerGroup  = '';
  addIocLoading        = false;
  addIocResult: { status: string; message: string } | null = null;

  // ── Watchlist ─────────────────────────────────────────────────────────────
  watchlist: any[]    = [];
  loadingWatchlist    = false;
  deletingIoc: string | null = null;
  watchlistFilter     = '';

  // ── Geo Intel ─────────────────────────────────────────────────────────────
  geoData: any[] = [];
  loadingGeo     = false;
  maxGeoCount    = 1;

  // ── Auth ──────────────────────────────────────────────────────────────────
  sensorIds: string[] = [];

  // ── Icons ─────────────────────────────────────────────────────────────────
  SearchIcon      = Search;
  ShieldCheckIcon = ShieldCheck;
  AlertIcon       = CircleAlert;
  RefreshIcon     = RefreshCw;
  HashIcon        = Hash;
  BellIcon        = Bell;
  PlusIcon        = Plus;
  TrashIcon       = Trash2;
  GlobeIcon       = Globe;
  DatabaseIcon    = Database;
  LayersIcon      = Layers;
  DownloadIcon    = Download;
  XIcon           = X;
  MapIcon         = LucideMap;
  CheckCircleIcon = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;
  ActivityIcon    = Activity;
  TrendingUpIcon  = TrendingUp;
  ExternalLinkIcon = ExternalLink;
  FilterIcon      = Filter;
  ChevronUpIcon   = ChevronUp;
  ChevronDownIcon = ChevronDown;
  EyeIcon         = Eye;
  CpuIcon         = Cpu;
  FileWarningIcon = FileWarning;

  private subs: Subscription[] = [];
  private processedAlertHits = new Map<string, number>();

  constructor(
    private api: Api,
    private notifications: Notifications,
    private cdr: ChangeDetectorRef,
    private auth: AuthService
  ) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.loadIntel();

    this.subs.push(
      this.notifications.alerts$.subscribe(alerts => {
        this.liveAlerts = alerts.slice(0, 20);
        this.syncDetectedNetworkAlerts(alerts);
        this.cdr.detectChanges();
      })
    );
    this.subs.push(
      this.notifications.unreadCount$.subscribe(count => {
        this.newAlertCount = count;
        this.cdr.detectChanges();
      })
    );
  }

  // ── Data loaders ─────────────────────────────────────────────────────────

  loadIntel() {
    this.loading = true;
    this.api.getThreatIntel().subscribe({
      next: (data: any) => {
        this.totalMaliciousIps     = data.total_malicious_ips     || 0;
        this.totalMaliciousHashes  = data.total_malicious_hashes  || 0;
        this.totalMaliciousDomains = data.total_malicious_domains || 0;
        this.source        = data.source || 'abuse.ch';
        this.detectedInNetwork = data.detected_in_network || [];
        this.feedSources   = data.sources || [];
        this.lastRefresh   = data.last_refresh ? `${data.last_refresh} UTC` : '';
        this.syncDetectedNetworkAlerts(this.liveAlerts);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  switchTab(tab: Tab) {
    this.activeTab = tab;
    if (tab === 'watchlist') this.loadWatchlist();
    if (tab === 'geo')       this.loadGeo();
  }

  loadWatchlist() {
    this.loadingWatchlist = true;
    this.api.getWatchlistIocs().subscribe({
      next: (res: any) => {
        this.watchlist = res.data || [];
        this.loadingWatchlist = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingWatchlist = false; this.cdr.detectChanges(); }
    });
  }

  loadGeo() {
    this.loadingGeo = true;
    this.api.getThreatMap().subscribe({
      next: (data: any) => {
        this.geoData     = (data.countries || []).slice(0, 15);
        this.maxGeoCount = Math.max(...this.geoData.map((c: any) => +c.count), 1);
        this.loadingGeo  = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingGeo = false; this.cdr.detectChanges(); }
    });
  }

  // ── IOC Lookup ────────────────────────────────────────────────────────────

  lookupIoc() {
    if (!this.searchQuery.trim()) return;
    this.searching    = true;
    this.lookupResult = null;
    this.api.lookupIoc(this.searchQuery.trim()).subscribe({
      next: (data: any) => { this.lookupResult = data; this.searching = false; this.cdr.detectChanges(); },
      error: ()          => { this.searching = false; this.cdr.detectChanges(); }
    });
  }

  clearLookup() {
    this.searchQuery  = '';
    this.lookupResult = null;
  }

  // ── Manual IOC ────────────────────────────────────────────────────────────

  addManualIoc() {
    if (!this.addIocValue.trim()) return;
    this.addIocLoading = true;
    this.addIocResult  = null;
    this.api.addManualIoc(this.addIocType, this.addIocValue.trim(), this.addIocAttackerGroup.trim()).subscribe({
      next: (res: any) => {
        this.addIocResult       = { status: 'ok', message: res.message || `${res.type} IOC added to watchlist` };
        this.addIocValue        = '';
        this.addIocAttackerGroup = '';
        this.addIocLoading      = false;
        if (this.activeTab === 'watchlist') this.loadWatchlist();
        this.cdr.detectChanges();
      },
      error: () => {
        this.addIocResult  = { status: 'error', message: 'Failed to add IOC' };
        this.addIocLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  deleteWatchlistIoc(ioc: any) {
    if (!confirm(`Remove IOC: ${ioc.value}?`)) return;
    this.deletingIoc = ioc.value;
    this.api.deleteWatchlistIoc(ioc.value).subscribe({
      next: () => {
        this.watchlist   = this.watchlist.filter(i => i.value !== ioc.value);
        this.deletingIoc = null;
        this.loadWatchlist();
      },
      error: () => { this.deletingIoc = null; this.cdr.detectChanges(); }
    });
  }

  // ── Detected table sort/filter/export ────────────────────────────────────

  get filteredDetected() {
    let list = [...this.detectedInNetwork];
    if (this.filterText.trim()) {
      const f = this.filterText.toLowerCase();
      list = list.filter(d => d.src_ip?.includes(f) || d.dst_ip?.includes(f));
    }
    list.sort((a, b) => {
      const va = a[this.sortField] ?? 0;
      const vb = b[this.sortField] ?? 0;
      return this.sortDir === 'desc' ? (vb > va ? 1 : -1) : (va > vb ? 1 : -1);
    });
    return list;
  }

  sortBy(field: string) {
    if (this.sortField === field) {
      this.sortDir = this.sortDir === 'desc' ? 'asc' : 'desc';
    } else {
      this.sortField = field;
      this.sortDir   = 'desc';
    }
  }

  exportCsv() {
    const rows = this.filteredDetected;
    const csv  = [
      'Source IP,Destination IP,Hits,Last Seen,Status',
      ...rows.map(r => `${r.src_ip},${r.dst_ip},${r.hits},${this.getTimestamp(r.last_seen)},THREAT DETECTED`)
    ].join('\n');
    const blob      = new Blob([csv], { type: 'text/csv' });
    const objectUrl = URL.createObjectURL(blob);
    const a         = document.createElement('a');
    a.href          = objectUrl;
    a.download      = `threat-intel-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(objectUrl);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  clearAlerts() {
    this.notifications.clearAlerts();
    this.cdr.detectChanges();
  }

  iocTypeBadge(type: string): string {
    switch (type) {
      case 'ip':     return 'type-ip';
      case 'domain': return 'type-domain';
      case 'hash':   return 'type-hash';
      case 'ja3':    return 'type-ja3';
      case 'url':    return 'type-url';
      default:       return 'type-ip';
    }
  }

  iocTypeLabel(type: string): string {
    const map: Record<string,string> = {
      ip: 'IP', domain: 'DOMAIN', hash: 'HASH', ja3: 'JA3', url: 'URL'
    };
    return map[type] || type.toUpperCase();
  }

  feedTypeIcon(type: string): string {
    if (type === 'IP')            return '🔴';
    if (type === 'File Hash')     return '🔵';
    if (type === 'Domain/URL')    return '🟡';
    return '⚪';
  }

  feedCount(type: string): number {
    if (type === 'IP')         return this.totalMaliciousIps;
    if (type === 'File Hash')  return this.totalMaliciousHashes;
    if (type === 'Domain/URL') return this.totalMaliciousDomains;
    return 0;
  }

  countryFlag(code: string): string {
    if (!code || code.length !== 2) return '🌍';
    return code.toUpperCase().replace(/./g, c =>
      String.fromCodePoint(127397 + c.charCodeAt(0))
    );
  }

  geoBarPct(count: number): number {
    return Math.round((count / this.maxGeoCount) * 100);
  }

  get watchlistFiltered() {
    if (!this.watchlistFilter.trim()) return this.watchlist;
    const f = this.watchlistFilter.toLowerCase();
    return this.watchlist.filter(i => i.value?.toLowerCase().includes(f) || i.type?.includes(f));
  }

  getTimestamp(ts: number): string {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString();
  }

  private syncDetectedNetworkAlerts(alerts: ThreatNotification[]) {
    for (const alert of alerts) {
      const key = alert.id;
      const existing   = this.detectedInNetwork.find(d => d.src_ip === alert.src_ip);
      const processedHits = this.processedAlertHits.get(key) || 0;
      const newHits    = Math.max((alert.hits || 1) - processedHits, 0);
      if (newHits === 0) continue;
      this.processedAlertHits.set(key, alert.hits || 1);
      if (existing) {
        existing.hits     += newHits;
        existing.last_seen = Math.floor(Date.now() / 1000);
      } else {
        this.detectedInNetwork.unshift({
          src_ip:    alert.src_ip,
          dst_ip:    alert.dst_ip,
          hits:      alert.hits || 1,
          last_seen: Math.floor(Date.now() / 1000),
        });
      }
    }
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
