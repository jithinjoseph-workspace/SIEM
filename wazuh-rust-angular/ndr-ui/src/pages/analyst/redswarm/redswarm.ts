import { Component, OnInit, OnDestroy, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Zap, Shield, RefreshCw, AlertTriangle, CheckCircle2, XCircle, AlertOctagon,
  Play, Pause, Flame, Eye, Lock, Terminal, ShieldAlert, Cpu, Check, ArrowRight
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  SwarmStatusReport, SwarmCampaign, SwarmExecutionRecord,
  SynthesizedRuleDraft, PurpleHeatmapData, SwarmExecutionMode
} from '../../../services/siem/siem.models';

@Component({
  selector: 'app-redswarm',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './redswarm.html',
  styleUrl: './redswarm.css',
})
export class RedswarmComponent implements OnInit, OnDestroy {
  private siem = inject(SiemService);

  // Icons
  ZapIcon = Zap;
  ShieldIcon = Shield;
  RefreshIcon = RefreshCw;
  AlertTriangleIcon = AlertTriangle;
  CheckCircleIcon = CheckCircle2;
  XCircleIcon = XCircle;
  OctagonIcon = AlertOctagon;
  PlayIcon = Play;
  PauseIcon = Pause;
  FlameIcon = Flame;
  EyeIcon = Eye;
  LockIcon = Lock;
  TerminalIcon = Terminal;
  ShieldAlertIcon = ShieldAlert;
  CpuIcon = Cpu;
  CheckIcon = Check;
  ArrowRightIcon = ArrowRight;

  // State Signals
  loading = signal<boolean>(false);
  status = signal<SwarmStatusReport | null>(null);
  campaigns = signal<SwarmCampaign[]>([]);
  history = signal<SwarmExecutionRecord[]>([]);
  gaps = signal<SynthesizedRuleDraft[]>([]);
  appliedRules = signal<SynthesizedRuleDraft[]>([]);
  heatmap = signal<PurpleHeatmapData | null>(null);

  // Tab navigation
  activeTab = signal<'feed' | 'gaps' | 'heatmap' | 'campaigns'>('feed');

  // Modal / Execution state
  isExecutingManual = signal<boolean>(false);
  /** `id|platform`: some technique ids exist for both systems */
  manualTechniqueId = signal<string>('T1110.001|linux');
  catalog = signal<{ id: string; name: string; tactic: string; platform: string }[]>([]);
  manualMode = signal<SwarmExecutionMode>('safe_telemetry_only');
  manualResult = signal<string | null>(null);

  // Rule detail modal
  selectedRuleDraft = signal<SynthesizedRuleDraft | null>(null);
  ruleDeployMessage = signal<string | null>(null);
  /** A failed kill-switch / campaign change, shown on the page. */
  actionError = signal<string | null>(null);

  /** Rounds run in the background: the page follows them. */
  private timer?: ReturnType<typeof setInterval>;
  /** The page could not reach the server. */
  loadError = signal<string | null>(null);

  ngOnInit() {
    this.refreshAll();
    this.siem.getRedSwarmCatalog().subscribe({ next: (c) => this.catalog.set(c || []), error: () => this.catalog.set([]) });
    this.timer = setInterval(() => this.refreshAll(), 30_000);
  }

  ngOnDestroy() {
    if (this.timer) clearInterval(this.timer);
  }

  modeLabel(mode: string | undefined): string {
    return mode === 'safe_telemetry_only' ? 'Simulation' : mode || '—';
  }

  refreshAll() {
    this.loading.set(true);
    this.siem.getRedSwarmStatus().subscribe({
      next: (s) => { this.status.set(s); this.loadError.set(null); },
      error: (err) => this.loadError.set(err?.error?.message || 'Red Swarm could not be loaded: the server did not answer.')
    });

    this.siem.getRedSwarmAppliedRules().subscribe({
      next: (r) => this.appliedRules.set(r || []),
      error: () => {}
    });

    this.siem.getRedSwarmCampaigns().subscribe({
      next: (c) => this.campaigns.set(c),
      error: () => {}
    });

    this.siem.getRedSwarmHistory().subscribe({
      next: (h) => this.history.set(h),
      error: () => {}
    });

    this.siem.getRedSwarmGaps().subscribe({
      next: (g) => this.gaps.set(g),
      error: () => {}
    });

    this.siem.getRedSwarmHeatmap().subscribe({
      next: (hm) => {
        this.heatmap.set(hm);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  toggleKillSwitch() {
    const currentState = this.status()?.kill_switch_active ?? false;
    const nextState = !currentState;
    this.actionError.set(null);
    this.siem.toggleRedSwarmKillSwitch(nextState).subscribe({
      next: (res) => {
        this.status.set({ ...res.swarm_status, kill_switch_active: res.kill_switch_active });
        if (res.saved === false) this.actionError.set('The kill switch is set, but it could not be saved: it would not hold after a server restart.');
        this.refreshAll();
      },
      error: (err) => this.actionError.set(err?.error?.message || 'The kill switch could not be changed.')
    });
  }

  toggleCampaign(campaignId: string) {
    this.actionError.set(null);
    this.siem.toggleRedSwarmCampaign(campaignId).subscribe({
      next: () => this.refreshAll(),
      error: (err) => this.actionError.set(err?.error?.message || 'The campaign could not be changed.')
    });
  }

  runSingleAttack() {
    this.isExecutingManual.set(true);
    this.manualResult.set(null);
    this.siem.runRedSwarmSingleRound({
      technique_id: this.manualTechniqueId().split('|')[0],
      platform: this.manualTechniqueId().split('|')[1],
      // the server picks one of the tenant's own computers of that system
      mode: this.manualMode()
    }).subscribe({
      next: (res) => {
        this.isExecutingManual.set(false);
        const v = res.record.verification;
        this.manualResult.set(`Verdict: ${v.verdict.replace(/_/g, ' ').toUpperCase()} on ${res.record.target_agent_name} - ${v.reason}`);
        this.refreshAll();
      },
      error: (err) => {
        this.isExecutingManual.set(false);
        this.manualResult.set(`Error: ${err?.error?.message || err.message}`);
      }
    });
  }

  openRuleModal(draft: SynthesizedRuleDraft) {
    this.selectedRuleDraft.set(draft);
    this.ruleDeployMessage.set(null);
  }

  closeRuleModal() {
    this.selectedRuleDraft.set(null);
    this.ruleDeployMessage.set(null);
  }

  rejectRule(draftId: string) {
    if (!confirm('Reject this draft rule? Red Swarm stops drafting rules for this technique.')) return;
    this.actionError.set(null);
    this.siem.rejectRedSwarmRule(draftId).subscribe({
      next: () => {
        this.closeRuleModal();
        this.refreshAll();
      },
      error: (err) => this.actionError.set(err?.error?.message || 'The draft could not be rejected.')
    });
  }

  /** The deploy message is an error (shown red). */
  ruleDeployFailed = signal<boolean>(false);

  approveAndDeployRule(draftId: string) {
    this.actionError.set(null);
    this.siem.approveAndDeployRule(draftId).subscribe({
      next: (res: any) => {
        this.ruleDeployFailed.set(false);
        this.ruleDeployMessage.set(`✓ Applied as rule ${res?.rule_id} (etc/rules/redswarm_rules.xml); the analysis engine checked the rules and reloaded them. The next round of this attack shows whether it is caught.`);
        // the modal shows the draft as it is now
        if (res?.rule && this.selectedRuleDraft()) this.selectedRuleDraft.set(res.rule);
        this.refreshAll();
      },
      error: (err) => {
        this.ruleDeployFailed.set(true);
        const msg = `Not applied: ${err?.error?.message || err.message}`;
        if (this.selectedRuleDraft()) this.ruleDeployMessage.set(msg); else this.actionError.set(msg);
      }
    });
  }

  rollbackRule(ruleId: string) {
    if (!confirm('Roll back this rule? It is removed from the analysis engine, and Red Swarm may draft a new rule if the attack is missed again.')) return;
    this.actionError.set(null);
    this.siem.rollbackRedSwarmRule(ruleId).subscribe({
      next: () => this.refreshAll(),
      error: (err) => this.actionError.set(err?.error?.message || 'The rule could not be rolled back.')
    });
  }
}
