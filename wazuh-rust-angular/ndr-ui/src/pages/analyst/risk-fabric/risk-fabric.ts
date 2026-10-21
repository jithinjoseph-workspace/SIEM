import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Network,
  Shield,
  ShieldAlert,
  Clock,
  Activity,
  UserCheck,
  Sparkles,
  Plus,
  Trash2,
  Edit3,
  CheckCircle2,
  AlertTriangle,
  Layers,
  RefreshCw,
  Play,
  ArrowRight,
  Sliders,
  Check,
  X,
  Building,
  Target
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  BusinessProcessDefinition,
  BusinessTimeWindow,
  RiskFabricSummary,
  RiskEvaluationRequest,
  RiskFabricScore,
  Alert
} from '../../../services/siem/siem.models';

type RiskFabricTab = 'overview' | 'simulator' | 'processes' | 'windows' | 'live_alerts';

@Component({
  selector: 'app-risk-fabric',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './risk-fabric.html',
  styleUrl: './risk-fabric.css',
})
export class RiskFabric implements OnInit {
  private siem = inject(SiemService);

  // Icons
  NetworkIcon = Network;
  ShieldIcon = Shield;
  ShieldAlertIcon = ShieldAlert;
  ClockIcon = Clock;
  ActivityIcon = Activity;
  UserCheckIcon = UserCheck;
  SparklesIcon = Sparkles;
  PlusIcon = Plus;
  TrashIcon = Trash2;
  EditIcon = Edit3;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  LayersIcon = Layers;
  RefreshIcon = RefreshCw;
  PlayIcon = Play;
  ArrowRightIcon = ArrowRight;
  SlidersIcon = Sliders;
  ConfirmIcon = Check;
  CancelIcon = X;
  BuildingIcon = Building;
  TargetIcon = Target;

  activeTab = signal<RiskFabricTab>('overview');
  isLoading = signal<boolean>(false);
  errorMessage = signal<string | null>(null);
  successMessage = signal<string | null>(null);

  // Data signals
  summary = signal<RiskFabricSummary>({
    total_processes: 0,
    active_time_windows: 0,
    average_dynamic_risk: 0,
    catastrophic_alerts_count: 0,
    critical_alerts_count: 0,
    high_alerts_count: 0,
    medium_alerts_count: 0,
    low_alerts_count: 0,
    top_critical_processes: [],
  });

  processes = signal<BusinessProcessDefinition[]>([]);
  windows = signal<BusinessTimeWindow[]>([]);
  alerts = signal<Alert[]>([]);

  // Simulator Form State
  simAgentName = signal<string>('srv-prod-ubuntu-01');
  simAgentIp = signal<string>('192.168.10.15');
  simUser = signal<string>('administrator');
  simRuleLevel = signal<number>(10);
  simRuleId = signal<number>(100101);
  simRuleDesc = signal<string>('Brute Force Detection: Multiple failed authentications in short window');
  simResult = signal<RiskFabricScore | null>(null);
  simCalculating = signal<boolean>(false);

  // Process Modal State
  isProcessModalOpen = signal<boolean>(false);
  editingProcessId = signal<string | null>(null);
  procFormName = signal<string>('');
  procFormDesc = signal<string>('');
  procFormCriticality = signal<string>('Mission-Critical');
  procFormAssetWeight = signal<number>(2.0);
  procFormIdentityWeight = signal<number>(1.5);
  procFormAssetPatterns = signal<string>('');
  procFormIdentityPatterns = signal<string>('');
  procFormImpactTemplate = signal<string>('');
  procFormEnabled = signal<boolean>(true);

  // Window Modal State
  isWindowModalOpen = signal<boolean>(false);
  editingWindowId = signal<string | null>(null);
  winFormName = signal<string>('');
  winFormDesc = signal<string>('');
  winFormMultiplier = signal<number>(1.4);
  winFormType = signal<string>('recurring_schedule');
  winFormActive = signal<boolean>(true);
  winFormTargetProcs = signal<string>('');

  ngOnInit() {
    this.loadAllData();
    this.runSimulation();
  }

  loadAllData() {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    // Fetch summary
    this.siem.getRiskFabricSummary().subscribe({
      next: (sum) => this.summary.set(sum),
      error: (e) => console.error('Failed to load risk summary', e),
    });

    // Fetch processes
    this.siem.getRiskFabricProcesses().subscribe({
      next: (procs) => this.processes.set(procs),
      error: (e) => console.error('Failed to load processes', e),
    });

    // Fetch time windows
    this.siem.getRiskFabricWindows().subscribe({
      next: (wins) => this.windows.set(wins),
      error: (e) => console.error('Failed to load time windows', e),
    });

    // Fetch recent alerts to display Risk Fabric enrichment
    this.siem.getAlerts().subscribe({
      next: (alts) => {
        this.alerts.set(alts);
        this.isLoading.set(false);
      },
      error: (e) => {
        this.isLoading.set(false);
        console.error('Failed to load alerts', e);
      },
    });
  }

  runSimulation() {
    this.simCalculating.set(true);
    const req: RiskEvaluationRequest = {
      rule_level: this.simRuleLevel(),
      rule_id: this.simRuleId(),
      rule_description: this.simRuleDesc(),
      agent_name: this.simAgentName(),
      agent_ip: this.simAgentIp(),
      user: this.simUser() || undefined,
    };

    this.siem.evaluateRisk(req).subscribe({
      next: (res) => {
        this.simResult.set(res);
        this.simCalculating.set(false);
      },
      error: (err) => {
        console.error('Simulation error', err);
        this.simCalculating.set(false);
      },
    });
  }

  loadSimulationScenario(scenario: 'pci_breach' | 'ad_takeover' | 'dev_noise' | 'dmz_probe') {
    if (scenario === 'pci_breach') {
      this.simAgentName.set('srv-prod-ubuntu-01');
      this.simAgentIp.set('192.168.10.15');
      this.simUser.set('cashier_svc');
      this.simRuleLevel.set(12);
      this.simRuleId.set(100104);
      this.simRuleDesc.set('Data Exfiltration: Outbound payload exceeds 100MB to unclassified external IP');
    } else if (scenario === 'ad_takeover') {
      this.simAgentName.set('hq-dc-01');
      this.simAgentIp.set('10.0.0.5');
      this.simUser.set('administrator');
      this.simRuleLevel.set(10);
      this.simRuleId.set(100105);
      this.simRuleDesc.set('Privilege Escalation: User created and immediately added to Domain Admins group');
    } else if (scenario === 'dev_noise') {
      this.simAgentName.set('dev-sandbox-02');
      this.simAgentIp.set('10.200.4.12');
      this.simUser.set('intern_qa');
      this.simRuleLevel.set(8);
      this.simRuleId.set(100101);
      this.simRuleDesc.set('Brute Force: Failed SSH passwords on staging cluster');
    } else if (scenario === 'dmz_probe') {
      this.simAgentName.set('dmz-web-nginx');
      this.simAgentIp.set('172.16.0.10');
      this.simUser.set('www-data');
      this.simRuleLevel.set(9);
      this.simRuleId.set(100107);
      this.simRuleDesc.set('C2 Beacon Detection: Periodic outbound HTTPS telemetry with low jitter');
    }
    this.runSimulation();
  }

  openNewProcessModal() {
    this.editingProcessId.set(null);
    this.procFormName.set('');
    this.procFormDesc.set('');
    this.procFormCriticality.set('Mission-Critical');
    this.procFormAssetWeight.set(2.0);
    this.procFormIdentityWeight.set(1.5);
    this.procFormAssetPatterns.set('*pay*, *swift*, 192.168.10.*');
    this.procFormIdentityPatterns.set('admin*, *cashier*, svc_*');
    this.procFormImpactTemplate.set('Critical asset or privileged identity compromised; immediate containment mandatory.');
    this.procFormEnabled.set(true);
    this.isProcessModalOpen.set(true);
  }

  editProcess(p: BusinessProcessDefinition) {
    this.editingProcessId.set(p.id);
    this.procFormName.set(p.name);
    this.procFormDesc.set(p.description);
    this.procFormCriticality.set(p.criticality);
    this.procFormAssetWeight.set(p.asset_weight);
    this.procFormIdentityWeight.set(p.identity_weight);
    this.procFormAssetPatterns.set(p.asset_patterns.join(', '));
    this.procFormIdentityPatterns.set(p.identity_patterns.join(', '));
    this.procFormImpactTemplate.set(p.impact_template);
    this.procFormEnabled.set(p.enabled);
    this.isProcessModalOpen.set(true);
  }

  saveProcess() {
    const id = this.editingProcessId() || `bp-${Date.now()}`;
    const assetPatterns = this.procFormAssetPatterns()
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const identityPatterns = this.procFormIdentityPatterns()
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    const proc: BusinessProcessDefinition = {
      id,
      name: this.procFormName(),
      description: this.procFormDesc(),
      criticality: this.procFormCriticality(),
      asset_weight: Number(this.procFormAssetWeight()),
      identity_weight: Number(this.procFormIdentityWeight()),
      asset_patterns: assetPatterns,
      identity_patterns: identityPatterns,
      impact_template: this.procFormImpactTemplate(),
      enabled: this.procFormEnabled(),
    };

    this.siem.saveRiskFabricProcess(proc).subscribe({
      next: () => {
        this.isProcessModalOpen.set(false);
        this.showSuccess('Business process saved successfully');
        this.loadAllData();
      },
      error: (e) => this.showError('Failed to save process: ' + e.message),
    });
  }

  deleteProcess(id: string) {
    if (confirm('Are you sure you want to delete this business process mapping?')) {
      this.siem.deleteRiskFabricProcess(id).subscribe({
        next: () => {
          this.showSuccess('Business process removed');
          this.loadAllData();
        },
        error: (e) => this.showError('Failed to delete process'),
      });
    }
  }

  toggleWindowActive(w: BusinessTimeWindow) {
    const updated: BusinessTimeWindow = { ...w, active: !w.active };
    this.siem.saveRiskFabricWindow(updated).subscribe({
      next: () => {
        this.showSuccess(`Window '${w.name}' ${updated.active ? 'activated' : 'deactivated'}`);
        this.loadAllData();
        this.runSimulation();
      },
      error: (e) => this.showError('Failed to toggle window'),
    });
  }

  deleteWindow(id: string) {
    if (confirm('Delete this operational time window?')) {
      this.siem.deleteRiskFabricWindow(id).subscribe({
        next: () => {
          this.showSuccess('Time window deleted');
          this.loadAllData();
        },
        error: (e) => this.showError('Failed to delete window'),
      });
    }
  }

  getTierClass(tier?: string): string {
    switch (tier?.toLowerCase()) {
      case 'catastrophic':
        return 'tier-catastrophic';
      case 'critical':
        return 'tier-critical';
      case 'high':
        return 'tier-high';
      case 'medium':
        return 'tier-medium';
      default:
        return 'tier-low';
    }
  }

  showSuccess(msg: string) {
    this.successMessage.set(msg);
    setTimeout(() => this.successMessage.set(null), 4000);
  }

  showError(msg: string) {
    this.errorMessage.set(msg);
    setTimeout(() => this.errorMessage.set(null), 5000);
  }
}
