import { Component, OnDestroy, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { Websocket } from '../../../services/websocket/websocket';
import { ArkimeService } from '../../../services/arkime/arkime';
import { EvidenceService } from '../../../services/evidence/evidence';
import { Subscription } from 'rxjs';
import { ActivatedRoute, Router } from '@angular/router';
import {
  LucideAngularModule,
  TriangleAlert, BellOff, ChevronDown, ChevronRight,
  Download, ExternalLink, Globe, Package, RefreshCw, ShieldAlert, X,
  Copy, ShieldCheck, Layers, GitBranch, ShieldX, ShieldOff, FolderPlus,
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';


import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
// Detection tags that are meaningful for grouping — must match Rust tag strings exactly
const DETECTION_TAGS = new Set([
  'dns-beaconing','port-scan','lateral-movement','credential-stuffing','slow-scan',
  'beaconing','threat-intel','ids-alert','abnormal-rst','data-staging',
  'internal-recon','volume-anomaly','new-external-contact','icmp-flood',
  'abnormal-hours','nxdomain-flood','dns-tunneling','tls-cert-anomaly',
  'protocol-misuse','large-volume-exfil','sensitive-country',
  'ip-conflict','sigma','dga','doh-evasion','malicious-domain',
  'c2',
]);

function primaryTag(tags: string[]): string {
  for (const t of tags) {
    if (DETECTION_TAGS.has(t)) return t;
  }
  return tags[0] || 'alert';
}

export interface AlertGroup {
  key:           string;
  tag:           string;
  sid?:          string;     // Suricata SID or Zeek tag extracted from raw tags
  src_ip:        string;
  src_hostname?: string;
  src_mac?:      string;
  dst_ip:        string;     // primary destination IP for this group
  dstIps:        string[];   // unique victim IPs/hostnames for group header display
  count:         number;
  maxScore:      number;
  severity:      string;
  latest:        string;
  alerts:        any[];
  expanded:      boolean;
}

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './alerts.html',
  styleUrl: './alerts.css',
})
export class Alerts implements OnInit, OnDestroy {
  // Raw store — all alerts loaded/streamed
  allAlerts: any[] = [];

  // Dismissed CIDs (local session)
  dismissedCids = new Set<string>();

  // Grouped view
  groups: AlertGroup[] = [];

  loading = true;

  // ── Filters ──────────────────────────────────────────────────────────────
  filterSeverity = '';          // '' | CRITICAL | HIGH | MEDIUM | LOW
  filterTag      = '';          // '' | dns-beaconing | port-scan | …
  filterMinScore = 0;           // 0–100
  filterSearch   = '';          // src_ip / dst_ip free text
  availableTags: string[] = []; // populated from loaded alerts

  // ── Active group suppressions (fetched from API on init, updated on suppress) ─
  // Used to filter both sessionStorage hits and live WebSocket hits.
  private groupSups: { src_ip: string; tag: string }[] = [];

  // ── Local asset lookup: IP → {name, mac} ──────────────────────────────────
  private assetMap = new Map<string, { name: string; mac: string }>();

  // ── Entity scores panel ───────────────────────────────────────────────────
  entityScores: any[] = [];
  entityScoresLoading = false;
  activeHostFilter = '';      // IP currently pinned via host card click

  // ── Toast ─────────────────────────────────────────────────────────────────
  toast = '';
  private toastTimer: any;

  // ── PCAP modal ────────────────────────────────────────────────────────────
  showPcapModal = false;
  pcapLoading   = false;
  pcapSessions: any[] = [];
  pcapError = '';

  // Icons
  ShieldAlertIcon  = ShieldAlert;
  TriangleAlertIcon = TriangleAlert;
  BellOffIcon      = BellOff;
  ChevronDownIcon  = ChevronDown;
  ChevronRightIcon = ChevronRight;
  DownloadIcon     = Download;
  ExternalLinkIcon = ExternalLink;
  GlobeIcon        = Globe;
  PackageIcon      = Package;
  RefreshIcon      = RefreshCw;
  XIcon            = X;
  CopyIcon         = Copy;
  ShieldCheckIcon  = ShieldCheck;
  LayersIcon       = Layers;
  GitBranchIcon    = GitBranch;
  ShieldXIcon      = ShieldX;
  ShieldOffIcon    = ShieldOff;
  FolderPlusIcon   = FolderPlus;

  // ── Tab ───────────────────────────────────────────────────────────────────
  activeTab: 'alerts' | 'incidents' = 'alerts';

  // ── Incidents ─────────────────────────────────────────────────────────────
  incidents:         any[]    = [];
  incidentsLoading            = false;
  selectedIncident:  any|null = null;
  isolatingIp                 = '';
  isolateResult               = '';
  isolatedIps                 = new Set<string>();

  private subs: Subscription[] = [];
  sensorIds: string[] = [];

  constructor(
    private api: Api,
    private ws: Websocket,
    private route: ActivatedRoute,
    private router: Router,
    private cdr: ChangeDetectorRef,
    private arkime: ArkimeService,
    private evidenceService: EvidenceService,
    private auth: AuthService,
  ) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();

    this.subs.push(
      this.route.queryParamMap.subscribe(params => {
        this.filterSeverity = params.get('severity')?.toUpperCase() || '';
        if (params.get('priority') === 'true') this.filterSeverity = 'HIGH';
        this.rebuild();
        this.cdr.detectChanges();
      })
    );

    // Load asset map first so names/MACs show in group rows without backend rebuild
    this.api.getAssets().subscribe({
      next: (assets: any[]) => {
        this.assetMap.clear();
        for (const a of assets) {
          if (!a.ip) continue;
          this.assetMap.set(a.ip, {
            name: a.custom_name || a.hostname || '',
            mac:  a.mac || '',
          });
        }
        this.rebuild();
        this.cdr.detectChanges();
      },
      error: reportRxjsError,
    });

    // Fetch active group suppressions first so WS filter is ready before hits arrive
    this.api.getActiveSuppressions().subscribe({
      next: (sups: any[]) => {
        this.groupSups = sups
          .filter(s => s.suppress_scope === 'group' && s.suppress_ip && s.signature_name)
          .map(s => ({ src_ip: s.suppress_ip, tag: s.signature_name }));
        this.loadAlerts();
      },
      error: () => this.loadAlerts(),
    });

    this.loadEntityScores();

    this.subs.push(
      this.ws.continuousHits$.subscribe(hits => {
        if (!hits?.length) return;
        const formatted = hits
          .map((h: any) => this.formatHit(h))
          .filter((h: any) => !this.isGroupSuppressedHit(h));
        if (!formatted.length) return;
        const existingCids = new Set(formatted.map((h: any) => h.community_id));
        this.allAlerts = [...formatted, ...this.allAlerts.filter(a => !existingCids.has(a.community_id))];
        if (this.allAlerts.length > 500) this.allAlerts = this.allAlerts.slice(0, 500);
        this.loading = false;
        this.rebuild();
        this.cdr.detectChanges();
      })
    );
  }

  private isGroupSuppressedHit(hit: any): boolean {
    if (!hit.src_ip) return false;
    return this.groupSups.some(s => {
      if (s.src_ip !== hit.src_ip) return false;
      // 'alert' is the fallback tag for hits with no detection tags — mirrors
      // the backend rule: empty(tags) AND empty(sigma_hits)
      if (s.tag === 'alert') {
        return !hit.tags?.length && !hit.sigma_hits?.length;
      }
      return hit.tags?.includes(s.tag) || hit.sigma_hits?.includes(s.tag);
    });
  }

  loadAlerts() {
    if (!this.allAlerts.length) this.loading = true;
    this.api.getAlerts().subscribe({
      next: (data: any[]) => {
        const fresh = data.map(h => this.formatHit(h));
        const freshCids = new Set(fresh.map((h: any) => h.community_id));
        // API result is authoritative (suppression applied server-side).
        // Preserve WS hits not in the API result (genuinely new) that aren't suppressed.
        const liveOnly = this.allAlerts.filter(a =>
          !freshCids.has(a.community_id) && !this.isGroupSuppressedHit(a)
        );
        this.allAlerts = [...fresh, ...liveOnly];
        if (this.allAlerts.length > 500) this.allAlerts = this.allAlerts.slice(0, 500);
        this.rebuild();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); },
    });
  }

  private formatHit(hit: any): any {
    const srcIp = hit.src_ip || hit.src || hit['agent-z']?.src || hit['agent-s']?.src || '';
    const dstIp = hit.dst_ip || hit.dst || hit['agent-z']?.dst || hit['agent-s']?.dst || '';
    const ts    = hit.timestamp ?? hit.ts ?? null;
    return {
      severity:    (hit.severity || 'LOW').toUpperCase(),
      description: hit.sigma_hits?.join(', ') || hit.tags?.join(', ') || 'Correlation hit',
      time:        this.formatAlertTime(ts),
      score:       hit.score ?? 0,
      community_id: hit.community_id || hit.cid || '',
      src_ip:      srcIp,
      dst_ip:      dstIp,
      src_country:  this.formatOrigin(srcIp, hit.src_country),
      dst_country:  hit.dst_country || '',
      threat_intel: !!hit.threat_intel,
      corroborated: !!hit.corroborated,
      sigma_hits:   hit.sigma_hits || [],
      tags:         hit.tags || [],
      src_asset:    hit.src_asset || null,
      dst_asset:    hit.dst_asset || null,
      dst_domain:   hit.dst_domain || '',
    };
  }

  // ── Rebuild groups from allAlerts after any filter change ─────────────────

  rebuild() {
    this.refreshAvailableTags();

    const filtered = this.allAlerts.filter(a => {
      if (this.dismissedCids.has(a.community_id)) return false;
      if (this.filterSeverity && a.severity !== this.filterSeverity) return false;
      if (this.filterTag && !a.tags.includes(this.filterTag)) return false;
      if (this.filterMinScore > 0 && (a.score ?? 0) < this.filterMinScore) return false;
      if (this.filterSearch) {
        const q = this.filterSearch.toLowerCase();
        if (!a.src_ip.includes(q) && !a.dst_ip.includes(q) &&
            !a.description.toLowerCase().includes(q)) return false;
      }
      return true;
    });

    // Group by primaryTag + src_ip + dst_ip (each attacker→target path is its own group)
    const map = new Map<string, AlertGroup>();
    for (const a of filtered) {
      const tag    = primaryTag(a.tags);
      const dstKey = a.dst_ip || '';
      const key    = `${tag}::${a.src_ip}::${dstKey}`;
      if (!map.has(key)) {
        const localAsset = this.assetMap.get(a.src_ip);
        const assetName  = localAsset?.name || a.src_asset?.hostname || undefined;
        const assetMac   = localAsset?.mac  || a.src_asset?.mac || undefined;
        map.set(key, {
          key, tag, src_ip: a.src_ip, dst_ip: dstKey,
          src_hostname: assetName,
          src_mac:      assetMac,
          dstIps: [],
          count: 0, maxScore: 0,
          severity: a.severity, latest: a.time,
          alerts: [], expanded: this.isExpanded(key),
        });
      }
      const g = map.get(key)!;
      if (!g.sid) {
        const sidTag = (a.tags as string[] || []).find((t: string) => /^(?:suricata|zeek):/i.test(t));
        if (sidTag) {
          g.sid = sidTag.replace(/^(?:suricata|zeek):/i, '');
        } else if (a.sigma_hits?.length) {
          g.sid = (a.sigma_hits[0] as string).replace(/suricata/gi, 'Agent-S').replace(/zeek/gi, 'Agent-Z');
        }
      }
      g.alerts.push(a);
      g.count++;
      if ((a.score ?? 0) > g.maxScore) {
        g.maxScore    = a.score ?? 0;
        g.severity    = a.severity;
        g.latest      = a.time;
      }
    }

    // Resolve unique victim IPs/hostnames per group (max 3 for display)
    for (const g of map.values()) {
      const seen = new Set<string>();
      for (const a of g.alerts) {
        const victim = a.dst_asset?.hostname || a.dst_domain || a.dst_ip;
        if (victim && victim !== '-' && !seen.has(victim)) {
          seen.add(victim);
          g.dstIps.push(victim);
          if (g.dstIps.length >= 3) break;
        }
      }
    }

    // Sort groups: severity order then score desc
    const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    this.groups = [...map.values()].sort((a, b) =>
      (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5) || b.maxScore - a.maxScore
    );
  }

  private expandedKeys = new Set<string>();
  private isExpanded(key: string): boolean { return this.expandedKeys.has(key); }

  toggleGroup(g: AlertGroup) {
    g.expanded = !g.expanded;
    if (g.expanded) this.expandedKeys.add(g.key);
    else this.expandedKeys.delete(g.key);
  }

  private refreshAvailableTags() {
    const seen = new Set<string>();
    for (const a of this.allAlerts) {
      for (const t of a.tags) {
        if (DETECTION_TAGS.has(t)) seen.add(t);
      }
    }
    this.availableTags = [...seen].sort();
  }

  // ── Summary counts ────────────────────────────────────────────────────────

  get totalAlerts()    { return this.allAlerts.length; }
  get criticalAlerts() { return this.allAlerts.filter(a => a.severity === 'CRITICAL').length; }
  get priorityAlerts() { return this.allAlerts.filter(a => a.severity === 'HIGH').length; }
  get mediumAlerts()   { return this.allAlerts.filter(a => a.severity === 'MEDIUM').length; }
  get intelAlerts()    { return this.allAlerts.filter(a => a.threat_intel).length; }
  get suppressedCount(){ return this.dismissedCids.size; }

  // ── Actions ───────────────────────────────────────────────────────────────

  suppress(alert: any) {
    // For sigma hits use the specific rule name; for other hits use the primary tag.
    // This prevents "suppress sigma from IP" from silencing ALL sigma rules on that host.
    const tag = alert.sigma_hits?.length ? alert.sigma_hits[0] : primaryTag(alert.tags);
    this.api.suppressAlert(alert.src_ip, alert.dst_ip, alert.community_id, tag, 24).subscribe({
      next: () => {
        this.dismissGroup(alert.src_ip, tag);
        this.showToast(`Suppressed "${tag}" from ${alert.src_ip} for 24h`);
      },
      // Not saved: keep the alert visible so it does not silently reappear later
      error: () => this.showToast(`Couldn't suppress "${tag}" from ${alert.src_ip} - nothing was saved`),
    });
  }

  suppressGroup(g: AlertGroup) {
    if (!g.src_ip) return; // guard: never suppress with an empty src_ip

    if (g.tag === 'sigma') {
      // Suppress each unique Sigma rule name in the group individually so we don't
      // create a blanket "suppress all sigma from IP" rule.
      const ruleNames = [...new Set(
        g.alerts.flatMap((a: any) => a.sigma_hits?.length ? a.sigma_hits : [])
      )];
      if (!ruleNames.length) return;
      let saved = 0;
      for (const ruleName of ruleNames) {
        this.api.suppressAlert(g.src_ip, '', '', ruleName, 24).subscribe({
          next: () => {
            saved++;
            if (!this.groupSups.some(s => s.src_ip === g.src_ip && s.tag === ruleName)) {
              this.groupSups.push({ src_ip: g.src_ip, tag: ruleName });
            }
            this.showToast(`Suppressed "${ruleName}" from ${g.src_ip} for 24h`);
            // hide the group only once every rule in it is saved
            if (saved === ruleNames.length) this.dismissGroup(g.src_ip, g.tag);
          },
          error: () => {
            this.showToast(`Couldn't suppress "${ruleName}" from ${g.src_ip} - nothing was saved`);
          },
        });
      }
      return;
    }

    // Non-sigma groups: suppress by primary tag as before
    this.api.suppressAlert(g.src_ip, '', '', g.tag, 24).subscribe({
      next: () => {
        if (!this.groupSups.some(s => s.src_ip === g.src_ip && s.tag === g.tag)) {
          this.groupSups.push({ src_ip: g.src_ip, tag: g.tag });
        }
        this.dismissGroup(g.src_ip, g.tag);
        this.showToast(`Suppressed ${g.count} × ${g.tag} from ${g.src_ip} for 24h`);
      },
      // Not saved: keep the group visible so it does not silently reappear later
      error: () => this.showToast(`Couldn't suppress ${g.tag} from ${g.src_ip} - nothing was saved`),
    });
  }

  private dismissGroup(srcIp: string, tag: string) {
    for (const a of this.allAlerts) {
      const matches = tag === 'alert'
        ? a.src_ip === srcIp && !a.tags?.length && !a.sigma_hits?.length
        : a.src_ip === srcIp && primaryTag(a.tags) === tag;
      if (matches) this.dismissedCids.add(a.community_id);
    }
    this.rebuild();
    this.cdr.detectChanges();
  }

  trustDomain(alert: any) {
    const domain = alert.dst_ip; // after Fix 3, dst_ip holds the queried domain for dns-beaconing
    if (!domain) return;
    this.api.addTrustedDomain(domain, 'dns_beacon', 'own', 'Added from alerts page').subscribe({
      next: () => {
        this.dismissedCids.add(alert.community_id);
        this.showToast(`Trusted domain: ${domain}`);
        this.rebuild();
        this.cdr.detectChanges();
      },
      error: () => this.showToast(`Failed to trust domain`),
    });
  }

  clearDismissed() {
    this.dismissedCids.clear();
    this.rebuild();
    this.cdr.detectChanges();
  }

  setFilterSeverity(s: string) {
    this.filterSeverity = this.filterSeverity === s ? '' : s;
    this.rebuild();
  }

  onFilterChange() { this.rebuild(); }

  // ── Entity scores ─────────────────────────────────────────────────────────

  loadEntityScores() {
    this.entityScoresLoading = true;
    this.api.getEntityScores().subscribe({
      next: (scores: any[]) => {
        this.entityScores = scores;
        this.entityScoresLoading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.entityScoresLoading = false; },
    });
  }

  filterByHost(ip: string) {
    if (this.activeHostFilter === ip) {
      this.activeHostFilter = '';
      this.filterSearch = '';
      this.loadAlerts();
      return;
    }
    this.activeHostFilter = ip;
    this.filterSearch = ip;
    // Fetch all alerts for this specific IP from the backend (bypasses the 200-alert window)
    this.loading = true;
    this.cdr.detectChanges();
    this.api.getAlerts(ip).subscribe({
      next: (data: any[]) => {
        this.allAlerts = data.map(h => this.formatHit(h));
        this.rebuild();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); },
    });
  }

  severityColor(sev: string): string {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return '#ff4444';
      case 'HIGH':     return '#ff8800';
      case 'MEDIUM':   return '#ffcc00';
      case 'LOW':      return '#44aaff';
      default:         return '#888888';
    }
  }

  // ── Block IP ──────────────────────────────────────────────────────────────

  blockIp(alert: any) {
    const ip = alert.src_ip;
    if (!ip) return;
    if (!confirm(`Block ${ip} for 24 hours?`)) return;
    this.api.manualBlock({
      src_ip: ip,
      enforcement: 'rst',
      duration_hours: 24,
      reason: `Manual block from alert — ${alert.description || alert.tags?.join(', ') || 'threat detected'}`,
    }).subscribe({
      next: () => this.showToast(`Blocked ${ip} for 24h`),
      error: () => this.showToast(`Failed to block ${ip}`),
    });
  }

  // ── Create Incident ───────────────────────────────────────────────────────

  createIncident(alert: any) {
    const title    = `${alert.tags?.[0] || alert.description || 'Threat'} — ${alert.src_ip}`;
    const analyst  = this.auth.getUser()?.username || '';
    this.api.createSoarCase({
      title,
      description: `Auto-created from alert.\n\nSource IP: ${alert.src_ip}\nDestination IP: ${alert.dst_ip}\nScore: ${alert.score}\nTags: ${alert.tags?.join(', ')}\nSigma hits: ${alert.sigma_hits?.join(', ') || 'none'}`,
      severity:    alert.severity,
      priority:    alert.severity === 'CRITICAL' ? 'P1' : alert.severity === 'HIGH' ? 'P2' : 'P3',
      src_ip:      alert.src_ip,
      dst_ip:      alert.dst_ip,
      community_id: alert.community_id,
      tags:        alert.tags || [],
      assigned_to: analyst,
    }).subscribe({
      next: (res: any) => {
        this.showToast(`Incident created — ${title}`);
        this.router.navigate(['/analyst/soar']);
      },
      error: () => this.showToast(`Failed to create incident`),
    });
  }

  blockIpGroup(g: AlertGroup) {
    const ip = g.src_ip;
    if (!ip) return;
    if (!confirm(`Block ${ip} for 24 hours? (${g.count} alerts in this group)`)) return;
    this.api.manualBlock({
      src_ip: ip,
      enforcement: 'rst',
      duration_hours: 24,
      reason: `Manual block from group — ${g.tag} (${g.count} alerts)`,
    }).subscribe({
      next: () => this.showToast(`Blocked ${ip} for 24h`),
      error: () => this.showToast(`Failed to block ${ip}`),
    });
  }

  createGroupIncident(g: AlertGroup) {
    const dst      = g.dst_ip || g.dstIps[0] || 'unknown';
    const title    = `${g.tag} — ${g.src_ip} → ${dst} (${g.count} alerts)`;
    const analyst  = this.auth.getUser()?.username || '';
    const allTags    = [...new Set(g.alerts.flatMap((a: any) => a.tags || []))];
    const allSigmas  = [...new Set(g.alerts.flatMap((a: any) => a.sigma_hits || []))];
    const ports      = [...new Set(g.alerts.map((a: any) => a.dst_port).filter(Boolean))];
    this.api.createSoarCase({
      title,
      description: `Auto-created from alert group.\n\nSource IP: ${g.src_ip}\nDestination IP: ${dst}\nAlert count: ${g.count}\nPorts seen: ${ports.slice(0, 20).join(', ')}${ports.length > 20 ? ` (+${ports.length - 20} more)` : ''}\nTags: ${allTags.join(', ')}\nSigma hits: ${allSigmas.join(', ') || 'none'}`,
      severity:    g.severity,
      priority:    g.severity === 'CRITICAL' ? 'P1' : g.severity === 'HIGH' ? 'P2' : 'P3',
      src_ip:      g.src_ip,
      dst_ip:      dst,
      community_id: g.alerts[0]?.community_id || '',
      tags:        allTags,
      assigned_to: analyst,
    }).subscribe({
      next: () => {
        this.showToast(`Incident created — ${g.count} alerts bundled`);
        this.router.navigate(['/analyst/soar']);
      },
      error: () => this.showToast(`Failed to create incident`),
    });
  }

  // ── Toast ──────────────────────────────────────────────────────────────────

  private showToast(msg: string) {
    clearTimeout(this.toastTimer);
    // setTimeout 0 defers past the current change-detection cycle, preventing NG0100
    setTimeout(() => {
      this.toast = msg;
      this.cdr.detectChanges();
      this.toastTimer = setTimeout(() => { this.toast = ''; this.cdr.detectChanges(); }, 3000);
    }, 0);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  getSeverityClass(severity: string) {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'sev-critical';
      case 'HIGH':     return 'sev-high';
      case 'MEDIUM':   return 'sev-medium';
      case 'INFO':     return 'sev-info';
      default:         return 'sev-low';
    }
  }

  getScoreClass(score: number) {
    if (score > 70) return 'score-high';
    if (score > 40) return 'score-medium';
    return 'score-low';
  }

  tagSid(tag: string): string | null {
    const m = tag.match(/^(?:suricata|zeek):(.+)$/i);
    return m ? m[1] : null;
  }

  tagLabel(tag: string): string {
    // Never expose vendor names — Suricata = Agent-S, Zeek = Agent-Z
    if (/^suricata:/i.test(tag)) return 'Agent-S';
    if (/^zeek:/i.test(tag))     return 'Agent-Z';
    const labels: Record<string, string> = {
      'ids-alert':            'Agent-S Alert',
      'dns-beaconing':        'DNS Beaconing',
      'dns-tunneling':        'DNS Tunneling',
      'port-scan':            'Port Scan',
      'slow-scan':            'Slow Scan',
      'lateral-movement':     'Lateral Movement',
      'credential-stuffing':  'Credential Stuffing',
      'beaconing':            'C2 Beaconing',
      'threat-intel':         'Threat Intel',
      'volume-anomaly':       'Volume Anomaly',
      'large-volume-exfil':   'Large Exfil',
      'icmp-flood':           'ICMP Flood',
      'nxdomain-flood':       'NX Domain Flood',
      'internal-recon':       'Internal Recon',
      'new-external-contact': 'New External',
      'data-staging':         'Data Staging',
      'abnormal-rst':         'Abnormal RST',
      'abnormal-hours':       'Abnormal Hours',
      'tls-cert-anomaly':     'TLS Anomaly',
      'protocol-misuse':      'Protocol Misuse',
      'sensitive-country':    'Sensitive Country',
      'ip-conflict':          'IP Conflict',
      'sigma':                'Sigma Rule',
      'dga':                  'DGA Domain',
      'doh-evasion':          'DoH Evasion',
      'malicious-domain':     'Malicious Domain',
      'c2':                   'C2 Framework',
      // Connection-state derived tags
      'mid-stream':           'Mid-Stream TCP',
      'midstream':            'Mid-Stream TCP',
      'half-open':            'Half-Open TCP',
      'connection-reset':     'Connection Reset',
      'compromised-host':     'Compromised Host',
      'alert':                'Correlation Hit',
      // Protocol tags (colon format from Zeek)
      'protocol:http':        'HTTP',
      'protocol:https':       'HTTPS',
      'protocol:dns':         'DNS',
      'protocol:smtp':        'SMTP',
      'protocol:ssh':         'SSH',
      'protocol:ftp':         'FTP',
      'protocol:smb':         'SMB',
      // Threat category tags
      't:exfiltration':       'Exfiltration',
      't:command-and-control':'C2 Traffic',
      't:lateral-movement':   'Lateral Movement',
      't:recon':              'Reconnaissance',
      't:persistence':        'Persistence',
    };
    if (labels[tag]) return labels[tag];
    // Strip t: or protocol: prefixes that aren't in the table above
    if (tag.startsWith('t:'))        return tag.slice(2).replace(/-/g, ' ');
    if (tag.startsWith('protocol:')) return tag.slice(9).toUpperCase();
    return tag.replace(/-/g, ' ');
  }

  ruleLabel(rule: string): string {
    return rule.replace(/suricata/gi, 'Agent-S').replace(/zeek/gi, 'Agent-Z');
  }

  tagColorClass(tag: string): string {
    if (/^suricata:/i.test(tag) || /^zeek:/i.test(tag))                                               return 'tc-intrusion';
    if (['ids-alert','tls-cert-anomaly','protocol-misuse'].includes(tag))                              return 'tc-intrusion';
    if (['port-scan','slow-scan','internal-recon','ip-conflict'].includes(tag))                        return 'tc-recon';
    if (['dns-beaconing','dns-tunneling','doh-evasion','nxdomain-flood','dga','malicious-domain'].includes(tag)) return 'tc-dns';
    if (['volume-anomaly','large-volume-exfil','icmp-flood'].includes(tag))                            return 'tc-volume';
    if (['lateral-movement','credential-stuffing','beaconing','new-external-contact','sensitive-country','t:command-and-control','t:lateral-movement'].includes(tag)) return 'tc-lateral';
    if (['threat-intel','t:exfiltration','compromised-host'].includes(tag))                           return 'tc-threat';
    if (['sigma'].includes(tag))                                                                       return 'tc-sigma';
    if (['data-staging','abnormal-rst','abnormal-hours','mid-stream','midstream','half-open','connection-reset','alert'].includes(tag)) return 'tc-anomaly';
    if (tag.startsWith('protocol:'))                                                                   return 'tc-default';
    if (tag.startsWith('t:'))                                                                          return 'tc-lateral';
    return 'tc-default';
  }

  isDnsBeaconing(alert: any): boolean {
    return alert.tags?.includes('dns-beaconing');
  }

  // ── PCAP ──────────────────────────────────────────────────────────────────

  viewPcap(cid: string) {
    if (!cid) return;
    this.pcapSessions = [];
    this.pcapError    = '';
    this.pcapLoading  = true;
    this.showPcapModal = true;
    this.arkime.getSessions({ cid, limit: 20 }).subscribe({
      next: (data: any) => { this.pcapSessions = data.sessions || []; this.pcapLoading = false; this.cdr.detectChanges(); },
      error: () => { this.pcapError = 'Failed to load PCAP sessions'; this.pcapLoading = false; this.cdr.detectChanges(); },
    });
  }

  openArkime(cid: string) {
    if (!cid) return;
    this.arkime.getSessionLink(cid).subscribe({
      next: (data: any) => { if (data.link) window.open(data.link, '_blank'); },
      error: () => this.showToast('Failed to open Arkime session'),
    });
  }

  copyIp(ip: string, event: MouseEvent) {
    event.stopPropagation();
    if (!ip) return;
    navigator.clipboard.writeText(ip).then(() => this.showToast(`Copied ${ip}`)).catch(() => {});
  }

  goToNetworkMap(ip: string, event: MouseEvent) {
    event.stopPropagation();
    if (!ip) return;
    this.router.navigate(['/analyst/network-map'], { queryParams: { ip } });
  }

  downloadPcap(sessionId: string)       { this.arkime.downloadPcap(sessionId); }
  downloadEvidence(cid: string)         { this.evidenceService.downloadBundle(cid); }
  viewTimeline(cid: string)             { this.router.navigate(['/analyst/evidence'], { queryParams: { cid } }); }
  formatBytes(bytes: number): string    {
    if (!bytes) return '0 B';
    const u = ['B','KB','MB','GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${u[i]}`;
  }

  private formatAlertTime(value: unknown): string {
    const d = this.parseAlertDate(value);
    return d ? d.toLocaleString() : '--';
  }

  private parseAlertDate(value: unknown): Date | null {
    if (value === null || value === undefined || value === '') return null;
    if (typeof value === 'number') {
      const ms = value > 9999999999 ? value : value * 1000;
      const d  = new Date(ms);
      return isNaN(d.getTime()) ? null : d;
    }
    const raw = String(value).trim();
    if (/^\d+$/.test(raw)) return this.parseAlertDate(Number(raw));
    const n = raw.includes('T') ? raw : raw.replace(' ', 'T');
    const z = /Z$|[+-]\d{2}:?\d{2}$/.test(n) ? n : `${n}Z`;
    const d = new Date(z);
    return isNaN(d.getTime()) ? null : d;
  }

  private formatOrigin(srcIp: string, country: string | undefined): string {
    if (country) return country;
    return this.isPrivateIp(srcIp) ? 'Internal network' : 'Origin unavailable';
  }

  private isPrivateIp(ip: string): boolean {
    return ip.startsWith('10.') || ip.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
      ['::1','fc','fd','fe80:'].some(p => ip.toLowerCase().startsWith(p));
  }

  ngOnDestroy() { this.subs.forEach(s => s.unsubscribe()); clearTimeout(this.toastTimer); }

  // ── Incidents tab ─────────────────────────────────────────────────────────

  switchTab(tab: 'alerts' | 'incidents') {
    this.activeTab = tab;
    if (tab === 'incidents' && this.incidents.length === 0) {
      this.loadIncidents();
    }
  }

  loadIncidents() {
    this.incidentsLoading = true;
    this.api.getIncidents().subscribe({
      next: (res: any) => {
        this.incidents = res.incidents || [];
        this.incidentsLoading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.incidentsLoading = false; this.cdr.detectChanges(); }
    });
    this.loadIsolatedIps();
  }

  // Isolations persist server-side (device_isolations table) — refresh the
  // in-memory set from there so "Isolated" survives a page reload instead of
  // only reflecting whatever happened in this browser session.
  loadIsolatedIps() {
    this.api.listIsolations().subscribe({
      next: (res: any) => {
        const rows = res.data || [];
        this.isolatedIps = new Set(rows.map((r: any) => r.target_ip));
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  openIncident(inc: any) {
    this.selectedIncident = inc === this.selectedIncident ? null : inc;
    this.isolateResult = '';
  }

  setIncidentStatus(inc: any, status: string) {
    this.api.updateIncidentStatus(inc.id, status).subscribe({
      next: () => {
        inc.status = status;
        this.showToast(`Incident marked as ${status}`);
        this.cdr.detectChanges();
      },
      error: () => this.showToast('Failed to update status')
    });
  }

  isolateIp(ip: string) {
    this.isolatingIp = ip;
    this.isolateResult = '';
    this.api.isolateDevice({ target_ip: ip, enforcement: 'arp', reason: 'Isolated via incident story' }).subscribe({
      next: (res: any) => {
        this.isolatingIp = '';
        const ok = res.status === 'ok';
        if (ok) this.isolatedIps.add(ip);
        this.isolateResult = ok ? `${ip} isolated` : (res.message || 'Failed');
        this.showToast(this.isolateResult);
        this.cdr.detectChanges();
      },
      error: () => {
        this.isolatingIp = '';
        this.isolateResult = 'Isolation failed';
        this.cdr.detectChanges();
      }
    });
  }

  incidentSeverityClass(sev: string): string {
    return sev === 'CRITICAL' ? 'sev-critical' : sev === 'HIGH' ? 'sev-high' : 'sev-medium';
  }

  formatIncidentTs(ts: number): string {
    return new Date(ts * 1000).toLocaleString();
  }
}
