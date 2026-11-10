import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { EvidenceService } from '../../../services/evidence/evidence';
import { AuthService } from '../../../services/auth/auth';


import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
const SEV_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

@Component({
  selector: 'app-evidence',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './evidence.html',
  styleUrl: './evidence.css'
})
export class EvidenceComponent implements OnInit {

  // ── Raw data signals ─────────────────────────────────────────────
  bundles       = signal<any[]>([]);
  selectedBundle = signal<any>(null);
  timeline      = signal<any>(null);
  annotations   = signal<any[]>([]);
  log           = signal<any[]>([]);
  loading       = signal(false);

  // ── Bundle detail signals ─────────────────────────────────────────
  bundleContents   = signal<any>(null);
  contentsLoading  = signal(false);
  contentsError    = signal('');
  verifyResult     = signal<any>(null);

  // ── AI verdict signals ────────────────────────────────────────────
  ariaVerdict       = signal<any>(null);
  ariaInvestigating = signal(false);
  ariaError         = signal('');

  // ── UI state signals ──────────────────────────────────────────────
  activeTab            = signal('bundles');
  activeContentSection = signal('attack_summary');
  expandedCids         = signal<Set<string>>(new Set());

  // ── Form fields (plain — no reactive tracking needed) ────────────
  holdReason = '';
  newNote    = '';
  newTag     = '';

  // ── Computed: corroboration stats ────────────────────────────────
  corroboratedCount = computed(() =>
    this.bundles().filter(b => b.correlation_status === 'corroborated').length
  );

  corrFilterActive = signal<string>('');   // '' | 'corroborated' | 'agent_z_only' | 'agent_s_only'

  corrLabel(status: string): { label: string; cls: string } {
    switch (status) {
      case 'corroborated': return { label: 'Z+S',   cls: 'corr-both' };
      case 'agent_s_only': return { label: 'S',     cls: 'corr-s'    };
      case 'multiflow':    return { label: 'Z+S+',  cls: 'corr-both' };
      default:             return { label: 'Z',     cls: 'corr-z'    };
    }
  }

  toggleCorrFilter(val: string) {
    this.corrFilterActive.set(this.corrFilterActive() === val ? '' : val);
  }

  // ── Computed: group bundles by community_id, highest sev first ────
  groupedBundles = computed(() => {
    const filter = this.corrFilterActive();
    const map = new Map<string, any[]>();
    for (const b of this.bundles()) {
      if (filter && b.correlation_status !== filter) continue;
      const cid = b.community_id || b.id;
      if (!map.has(cid)) map.set(cid, []);
      map.get(cid)!.push(b);
    }
    const groups = Array.from(map.entries()).map(([cid, alerts]) => {
      const sorted = [...alerts].sort((a, b) =>
        (SEV_ORDER[b.severity?.toUpperCase()] ?? 0) -
        (SEV_ORDER[a.severity?.toUpperCase()] ?? 0)
      );
      return { community_id: cid, primary: sorted[0], alerts: sorted };
    });
    groups.sort((a, b) =>
      (SEV_ORDER[b.primary.severity?.toUpperCase()] ?? 0) -
      (SEV_ORDER[a.primary.severity?.toUpperCase()] ?? 0)
    );
    return groups;
  });

  // ── Computed: outer grouping by src_ip→dst_ip pair ────────────────
  ipGroupedBundles = computed(() => {
    const filter = this.corrFilterActive();
    const map = new Map<string, any[]>();
    for (const b of this.bundles()) {
      if (filter && b.correlation_status !== filter) continue;
      const key = `${b.src_ip || ''}→${b.dst_ip || ''}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(b);
    }
    return Array.from(map.entries()).map(([key, items]) => {
      const [src_ip, dst_ip] = key.split('→');
      const maxSev = items.reduce((best, b) =>
        (SEV_ORDER[b.severity?.toUpperCase()] ?? 0) > (SEV_ORDER[best?.toUpperCase()] ?? 0) ? b.severity : best,
        'INFO'
      );
      return { key, src_ip, dst_ip, bundles: items, count: items.length, maxSev };
    }).sort((a, b) =>
      (SEV_ORDER[b.maxSev?.toUpperCase()] ?? 0) - (SEV_ORDER[a.maxSev?.toUpperCase()] ?? 0)
    );
  });

  expandedIpKeys = signal<Set<string>>(new Set());

  toggleIpGroup(key: string) {
    this.expandedIpKeys.update(s => {
      const next = new Set(s);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  private pendingCid:   string | null = null;
  private pendingSrcIp: string | null = null;
  private pendingDstIp: string | null = null;
  private auth = inject(AuthService);

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(
    private evidenceService: EvidenceService,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.route.queryParams.subscribe(params => {
      const cid = params['cid'];
      if (cid) this.pendingCid = cid;
      if (params['src_ip']) this.pendingSrcIp = params['src_ip'];
      if (params['dst_ip']) this.pendingDstIp = params['dst_ip'];
    });
    this.loadBundles();
  }

  loadBundles() {
    this.loading.set(true);
    this.evidenceService.listBundles().subscribe({
      next: (r: any) => {
        this.bundles.set(r.bundles || []);
        this.loading.set(false);
        const all = this.bundles();
        if (this.pendingCid) {
          const match = all.find(b => b.community_id === this.pendingCid);
          if (match) { this.pendingCid = null; this.selectBundle(match); }
        }
        // Auto-expand IP group from SOAR overlay params
        if (this.pendingSrcIp && this.pendingDstIp) {
          const key = `${this.pendingSrcIp}→${this.pendingDstIp}`;
          this.expandedIpKeys.set(new Set([key]));
          const firstInGroup = all.find(b => b.src_ip === this.pendingSrcIp && b.dst_ip === this.pendingDstIp);
          if (firstInGroup && !this.selectedBundle()) this.selectBundle(firstInGroup);
          this.pendingSrcIp = null; this.pendingDstIp = null;
        } else if (!this.selectedBundle() && this.ipGroupedBundles().length > 0) {
          const first = this.ipGroupedBundles()[0];
          this.expandedIpKeys.set(new Set([first.key]));
          this.selectBundle(first.bundles[0]);
        }
      },
      error: () => this.loading.set(false)
    });
  }

  selectBundle(b: any) {
    this.selectedBundle.set(b);
    this.activeTab.set('investigation');
    this.activeContentSection.set('attack_summary');
    this.loadTimeline(b.community_id);
    this.loadLog(b.community_id);
    this.loadAnnotations(b.id);
    this.loadBundleContents(b.id);
    this.loadVerdict(b.community_id);
  }

  loadVerdict(communityId: string) {
    this.ariaVerdict.set(null);
    this.ariaError.set('');
    this.evidenceService.getVerdict(communityId).subscribe({
      next: (r: any) => {
        if (r.status === 'ok' && r.verdict) {
          this.ariaVerdict.set(r.verdict);
        }
      },
      error: reportRxjsError
    });
  }

  runInvestigation(b: any) {
    this.ariaInvestigating.set(true);
    this.ariaError.set('');
    this.activeContentSection.set('aria_verdict');
    this.evidenceService.runInvestigation(b.community_id).subscribe({
      next: (r: any) => {
        this.ariaInvestigating.set(false);
        if (r.status === 'ok') {
          this.ariaVerdict.set(r);
        } else {
          this.ariaError.set(r.error || 'Investigation failed');
        }
      },
      error: () => {
        this.ariaInvestigating.set(false);
        this.ariaError.set('AI investigation failed — check AI provider configuration in Settings.');
      }
    });
  }

  verdictClass(verdict: string): string {
    if (verdict === 'TRUE_POSITIVE')  return 'verdict-true';
    if (verdict === 'FALSE_POSITIVE') return 'verdict-false';
    return 'verdict-suspicious';
  }

  verdictLabel(verdict: string): string {
    if (verdict === 'TRUE_POSITIVE')  return 'TRUE POSITIVE';
    if (verdict === 'FALSE_POSITIVE') return 'FALSE POSITIVE';
    return 'SUSPICIOUS';
  }

  loadBundleContents(bundleId: string) {
    this.contentsLoading.set(true);
    this.contentsError.set('');
    this.bundleContents.set(null);
    this.evidenceService.getBundleContents(bundleId).subscribe({
      next:  (data: any) => { this.bundleContents.set(data);  this.contentsLoading.set(false); },
      error: ()          => { this.contentsError.set('Failed to load bundle contents'); this.contentsLoading.set(false); }
    });
  }

  toggleGroup(group: any, event: Event) {
    event.stopPropagation();
    this.expandedCids.update(s => {
      const next = new Set(s);
      if (next.has(group.community_id)) next.delete(group.community_id);
      else next.add(group.community_id);
      return next;
    });
  }

  connStateDesc(state: string): string {
    const descriptions: {[k: string]: string} = {
      'S0': 'Connection attempt, no reply', 'S1': 'Established, not terminated',
      'S2': 'Closed by originator', 'S3': 'Closed by responder',
      'SF': 'Normal close', 'REJ': 'Connection rejected',
      'RSTO': 'Reset by originator', 'RSTR': 'Reset by responder',
      'RSTOS0': 'Originator reset, no reply', 'RSTRH': 'Reset by responder, no SYN',
      'SH': 'SYN then half close', 'SHR': 'Responder SYN, half close',
      'OTH': 'No SYN, mid-stream'
    };
    return descriptions[state] || '';
  }

  loadTimeline(cid: string) {
    this.evidenceService.getTimeline(cid).subscribe((r: any) => this.timeline.set(r));
  }

  loadLog(cid: string) {
    this.evidenceService.getLog(cid).subscribe((r: any) => this.log.set(r.log || []));
  }

  loadAnnotations(bundleId: string) {
    this.evidenceService.getAnnotations(bundleId).subscribe((r: any) => this.annotations.set(r.annotations || []));
  }

  download(b: any) { this.evidenceService.downloadBundle(b.community_id); }

  verify(b: any) {
    this.activeTab.set('verify');
    this.verifyResult.set(null);
    this.evidenceService.verifyBundle(b.id).subscribe({
      next:  (r: any) => this.verifyResult.set(r),
      error: ()       => this.verifyResult.set({
        status: 'ERROR', stored_sha256: '-', computed_sha256: '-',
        verified_at: new Date().toISOString(), verified_by: '-'
      })
    });
  }

  setHold(b: any, hold: boolean) {
    const reason = hold ? this.holdReason : 'Hold cleared';
    this.evidenceService.setLegalHold(b.id, hold, reason).subscribe(() => {
      this.loadBundles(); this.holdReason = '';
    });
  }

  filterRules(rules: any[]): any[] {
    if (!rules) return [];
    return rules.filter(r => {
      const name = (r.name || '').trim();
      return name.includes(' ') || name.length >= 8;
    });
  }

  addNote(b: any) {
    if (!this.newNote) return;
    this.evidenceService.annotate(b.id, b.community_id, this.newNote, this.newTag)
      .subscribe(() => {
        this.loadAnnotations(b.id); this.newNote = ''; this.newTag = '';
      });
  }

  hasAgentSLogs(): boolean {
    return (this.timeline()?.uid_logs ?? []).some((e: any) => e.source === 'agent-s');
  }

  sanitizeRuleName(name: any): string {
    return String(name || '')
      .replace(/\bSURICATA\b/gi, 'Agent-S')
      .replace(/\bZEEK\b/gi, 'Agent-Z');
  }
}
