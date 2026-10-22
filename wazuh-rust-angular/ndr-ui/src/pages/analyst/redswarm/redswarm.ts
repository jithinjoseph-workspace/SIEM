import { Component, OnInit, signal, computed, inject } from '@angular/core';
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
export class RedswarmComponent implements OnInit {
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
  heatmap = signal<PurpleHeatmapData | null>(null);

  // Tab navigation
  activeTab = signal<'feed' | 'gaps' | 'heatmap' | 'campaigns'>('feed');

  // Modal / Execution state
  isExecutingManual = signal<boolean>(false);
  manualTechniqueId = signal<string>('T1110.001');
  manualMode = signal<SwarmExecutionMode>('safe_telemetry_only');
  manualResult = signal<string | null>(null);

  // Rule detail modal
  selectedRuleDraft = signal<SynthesizedRuleDraft | null>(null);
  ruleDeployMessage = signal<string | null>(null);

  ngOnInit() {
    this.refreshAll();
  }

  refreshAll() {
    this.loading.set(true);
    this.siem.getRedSwarmStatus().subscribe({
      next: (s) => this.status.set(s),
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
    this.siem.toggleRedSwarmKillSwitch(nextState).subscribe({
      next: (res) => {
        this.status.set(res.swarm_status);
        this.refreshAll();
      }
    });
  }

  toggleCampaign(campaignId: string) {
    this.siem.toggleRedSwarmCampaign(campaignId).subscribe({
      next: () => this.refreshAll()
    });
  }

  runSingleAttack() {
    this.isExecutingManual.set(true);
    this.manualResult.set(null);
    this.siem.runRedSwarmSingleRound({
      technique_id: this.manualTechniqueId(),
      mode: this.manualMode(),
      target_agent_id: '001'
    }).subscribe({
      next: (res) => {
        this.isExecutingManual.set(false);
        this.manualResult.set(`Verdict: ${res.record.verification.verdict.toUpperCase()} - ${res.record.verification.reason}`);
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

  approveAndDeployRule(draftId: string) {
    this.siem.approveAndDeployRule(draftId).subscribe({
      next: () => {
        this.ruleDeployMessage.set('✓ Rule successfully approved, written to ruleset/0999-redswarm-synthesized.xml and staged!');
        this.refreshAll();
      },
      error: (err) => {
        this.ruleDeployMessage.set(`Failed to stage rule: ${err?.error?.message || err.message}`);
      }
    });
  }
}
