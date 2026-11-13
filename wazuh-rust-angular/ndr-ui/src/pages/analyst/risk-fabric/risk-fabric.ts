import { Component, OnInit, OnDestroy, signal, computed, inject } from '@angular/core';
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
  Target,
  Server,
  Terminal,
  Zap,
  Search,
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { Subscription } from 'rxjs';
import {
  BusinessProcessDefinition,
  BusinessTimeWindow,
  RiskFabricSummary,
  RiskEvaluationRequest,
  RiskFabricScore,
  Alert,
  Agent,
} from '../../../services/siem/siem.models';

type RiskFabricTab = 'overview' | 'simulator' | 'processes' | 'windows' | 'live_alerts';

@Component({
  selector: 'app-risk-fabric',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './risk-fabric.html',
  styleUrl: './risk-fabric.css',
})
export class RiskFabric implements OnInit, OnDestroy {
  private alertSub?: Subscription;
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
  ServerIcon = Server;
  TerminalIcon = Terminal;
  ZapIcon = Zap;
  SearchIcon = Search;

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
  availableAgents = signal<Agent[]>([]);

  // Filtering & Search State
  searchProcessQuery = signal<string>('');
  lastAlertTimestamp = signal<string>('Streaming active');

  // Computed Fleet Statistics
  fleetStats = computed(() => {
    const agents = this.availableAgents();
    const total = agents.length;
    const windows = agents.filter(
      (a) => a.os_type === 'windows' || a.name.toLowerCase().includes('win')
    ).length;
    const linux = agents.filter(
      (a) =>
        a.os_type === 'linux' ||
        a.name.toLowerCase().includes('linux') ||
        (!a.os_type && !a.name.toLowerCase().includes('win'))
    ).length;
    return { total, windows, linux };
  });

  filteredProcesses = computed(() => {
    const query = this.searchProcessQuery().toLowerCase().trim();
    if (!query) return this.processes();
    return this.processes().filter(
      (p) =>
        p.name.toLowerCase().includes(query) ||
        p.description.toLowerCase().includes(query) ||
        p.criticality.toLowerCase().includes(query) ||
        (p.asset_patterns || []).some((pat) => pat.toLowerCase().includes(query)) ||
        (p.group_patterns || []).some((gp) => gp.toLowerCase().includes(query)) ||
        (p.identity_patterns || []).some((ip) => ip.toLowerCase().includes(query))
    );
  });

  // Simulator Form State
  selectedSimAgentId = signal<string>('custom');
  simAgentName = signal<string>('win-node-7a5e');
  simAgentIp = signal<string>('192.168.1.142');
  simAgentOs = signal<string>('windows');
  simUser = signal<string>('administrator');
  simRuleLevel = signal<number>(10);
  simRuleId = signal<number>(100101);
  simRuleDesc = signal<string>(
    'Brute Force Detection: Multiple failed authentications in short window'
  );
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
  procFormGroupPatterns = signal<string>('');
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
  private summaryRefreshTimer: ReturnType<typeof setTimeout> | null = null;

  private isNoiseOrSimulationAlert(alert: Alert): boolean {
    const groups = alert.rule?.groups || [];
    if (groups.includes('redswarm_simulation')) return true;
    return (alert.rule?.level ?? 0) < 5;
  }

  private scheduleSummaryRefresh() {
    if (this.summaryRefreshTimer !== null) return;
    this.summaryRefreshTimer = setTimeout(() => {
      this.summaryRefreshTimer = null;
      this.siem.getRiskFabricSummary().subscribe({
        next: (sum) => this.summary.set(sum),
        error: () => {},
      });
    }, 3000);
  }

  ngOnInit() {
    this.loadAllData();
    this.runSimulation();
    this.alertSub = this.siem.getAlertStream().subscribe({
      next: (incomingAlert) => {
        if (this.isNoiseOrSimulationAlert(incomingAlert)) return;
        this.alerts.update((list) => {
          const deduped = list.filter((a) => a.id !== incomingAlert.id);
          return [incomingAlert, ...deduped.slice(0, 99)];
        });
        this.lastAlertTimestamp.set(new Date().toLocaleTimeString());
        this.scheduleSummaryRefresh();
      },
    });
  }

  ngOnDestroy() {
    this.alertSub?.unsubscribe();
    if (this.summaryRefreshTimer !== null) {
      clearTimeout(this.summaryRefreshTimer);
      this.summaryRefreshTimer = null;
    }
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

    // Fetch live agents for dynamic simulation targeting
    this.siem.getAgents().subscribe({
      next: (agents) => {
        this.availableAgents.set(agents);
        if (agents.length > 0 && this.selectedSimAgentId() === 'custom') {
          const first = agents[0];
          this.selectedSimAgentId.set(first.id);
          this.simAgentName.set(first.name);
          this.simAgentIp.set(first.ip);
          const isWin =
            first.os_type === 'windows' || first.name.toLowerCase().includes('win');
          this.simAgentOs.set(isWin ? 'windows' : 'linux');
          this.simUser.set(isWin ? 'administrator' : 'root');
          this.runSimulation();
        }
      },
      error: (e) => console.warn('Failed to load agents for simulation', e),
    });

    // Fetch recent alerts to display Risk Fabric enrichment
    this.siem.getAlerts(100, 5).subscribe({
      next: (alts) => {
        const seen = new Set<string>();
        const filtered = alts.filter((a) => {
          if (this.isNoiseOrSimulationAlert(a)) return false;
          if (!a.id || seen.has(a.id)) return false;
          seen.add(a.id);
          return true;
        });
        this.alerts.set(filtered);
        this.isLoading.set(false);
      },
      error: (e) => {
        this.isLoading.set(false);
        console.error('Failed to load alerts', e);
      },
    });
  }

  onSelectSimAgent(target: any) {
    const id = typeof target === 'string' ? target : (target?.target as HTMLSelectElement)?.value;
    this.selectedSimAgentId.set(id);
    if (id !== 'custom') {
      const match = this.availableAgents().find((a) => a.id === id);
      if (match) {
        this.simAgentName.set(match.name);
        this.simAgentIp.set(match.ip);
        const isWin =
          match.os_type === 'windows' || match.name.toLowerCase().includes('win');
        this.simAgentOs.set(isWin ? 'windows' : 'linux');
        this.simUser.set(isWin ? 'administrator' : 'root');
      }
    }
    this.runSimulation();
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
      os_type: this.simAgentOs() || undefined,
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

  loadAlertIntoSimulator(a: Alert) {
    this.activeTab.set('simulator');
    this.selectedSimAgentId.set(a.agent.id || 'custom');
    this.simAgentName.set(a.agent.name || 'node-endpoint');
    this.simAgentIp.set(a.agent.ip || '127.0.0.1');
    const isWin =
      (a.agent as any).os_type === 'windows' ||
      (a.agent.name || '').toLowerCase().includes('win');
    this.simAgentOs.set(isWin ? 'windows' : 'linux');

    // Resolve user from alert if present
    const user =
      (a.data as any)?.win?.eventdata?.targetUserName ||
      (a.data as any)?.win?.eventdata?.subjectUserName ||
      (a.data as any)?.audit?.auid ||
      (a.data as any)?.dstuser ||
      (isWin ? 'administrator' : 'root');

    this.simUser.set(user);
    this.simRuleLevel.set(a.rule?.level || 10);
    this.simRuleId.set(a.rule?.id || 100001);
    this.simRuleDesc.set(a.rule?.description || 'Real-time Security Event');
    this.runSimulation();
    this.showSuccess(`Alert #${a.rule?.id} from '${a.agent?.name}' loaded into Simulator`);
  }

  loadSimulationScenario(
    scenario: 'pci_breach' | 'ad_takeover' | 'dev_noise' | 'dmz_probe'
  ) {
    const agents = this.availableAgents();
    const winAgent = agents.find(
      (a) => a.os_type === 'windows' || a.name.toLowerCase().includes('win')
    );
    const linuxAgent = agents.find(
      (a) => a.os_type === 'linux' || a.name.toLowerCase().includes('linux')
    );

    if (scenario === 'pci_breach') {
      const target = linuxAgent || (agents.length > 0 ? agents[0] : null);
      this.selectedSimAgentId.set(target ? target.id : 'custom');
      this.simAgentName.set(target ? target.name : 'srv-pci-worker-01');
      this.simAgentIp.set(target ? target.ip : '10.0.4.15');
      this.simAgentOs.set('linux');
      this.simUser.set('cashier_svc');
      this.simRuleLevel.set(12);
      this.simRuleId.set(100104);
      this.simRuleDesc.set(
        'Data Exfiltration: Outbound payload exceeds 100MB to unclassified external IP'
      );
    } else if (scenario === 'ad_takeover') {
      const target = winAgent || (agents.length > 0 ? agents[0] : null);
      this.selectedSimAgentId.set(target ? target.id : 'custom');
      this.simAgentName.set(target ? target.name : 'dc01-corp-ad');
      this.simAgentIp.set(target ? target.ip : '192.168.1.10');
      this.simAgentOs.set('windows');
      this.simUser.set('administrator');
      this.simRuleLevel.set(10);
      this.simRuleId.set(100105);
      this.simRuleDesc.set(
        'Privilege Escalation: User created and immediately added to Domain Admins group'
      );
    } else if (scenario === 'dev_noise') {
      const target = linuxAgent || (agents.length > 0 ? agents[0] : null);
      this.selectedSimAgentId.set(target ? target.id : 'custom');
      this.simAgentName.set(target ? target.name : 'dev-sandbox-qa02');
      this.simAgentIp.set(target ? target.ip : '10.10.99.40');
      this.simAgentOs.set('linux');
      this.simUser.set('intern_qa');
      this.simRuleLevel.set(8);
      this.simRuleId.set(100101);
      this.simRuleDesc.set(
        'Brute Force: Failed SSH passwords on staging cluster'
      );
    } else if (scenario === 'dmz_probe') {
      const target = agents.length > 0 ? agents[0] : null;
      this.selectedSimAgentId.set(target ? target.id : 'custom');
      this.simAgentName.set(target ? target.name : 'dmz-web-nginx');
      this.simAgentIp.set(target ? target.ip : '172.16.0.10');
      this.simAgentOs.set('linux');
      this.simUser.set('www-data');
      this.simRuleLevel.set(9);
      this.simRuleId.set(100107);
      this.simRuleDesc.set(
        'C2 Beacon Detection: Periodic outbound HTTPS telemetry with low jitter'
      );
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
    this.procFormGroupPatterns.set('pci-dss, domain-controllers');
    this.procFormIdentityPatterns.set('admin*, *cashier*, svc_*');
    this.procFormImpactTemplate.set(
      'Critical asset or privileged identity compromised; immediate containment mandatory.'
    );
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
    this.procFormGroupPatterns.set((p.group_patterns || []).join(', '));
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
    const groupPatterns = this.procFormGroupPatterns()
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
      group_patterns: groupPatterns,
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
        this.showSuccess(
          `Window '${w.name}' ${updated.active ? 'activated' : 'deactivated'}`
        );
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
