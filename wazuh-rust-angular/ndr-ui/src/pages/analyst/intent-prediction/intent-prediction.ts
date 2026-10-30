import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import {
  LucideAngularModule,
  Target,
  ShieldAlert,
  Shield,
  ShieldCheck,
  AlertTriangle,
  Zap,
  Clock,
  Activity,
  ArrowRight,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Play,
  Crosshair,
  Lock,
  Layers,
  Cpu,
  Radio,
  Sliders,
  ExternalLink,
  ChevronRight,
  Info
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  EntityIntentDossier,
  IntentSummaryReport,
  PreemptiveAction,
  SimulationIntentRequest,
  ExecuteActionRequest,
  IntentHypothesisScore,
  KillChainMilestone,
  Agent
} from '../../../services/siem/siem.models';

@Component({
  selector: 'app-intent-prediction',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './intent-prediction.html',
  styleUrl: './intent-prediction.css'
})
export class IntentPrediction implements OnInit {
  private siem = inject(SiemService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);

  // Icons
  TargetIcon = Target;
  ShieldAlertIcon = ShieldAlert;
  ShieldIcon = Shield;
  ShieldCheckIcon = ShieldCheck;
  AlertTriangleIcon = AlertTriangle;
  ZapIcon = Zap;
  ClockIcon = Clock;
  ActivityIcon = Activity;
  ArrowRightIcon = ArrowRight;
  RefreshIcon = RefreshCw;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = CheckCircle2;
  XCircleIcon = XCircle;
  PlayIcon = Play;
  CrosshairIcon = Crosshair;
  LockIcon = Lock;
  LayersIcon = Layers;
  CpuIcon = Cpu;
  RadioIcon = Radio;
  SlidersIcon = Sliders;
  ExternalLinkIcon = ExternalLink;
  ChevronRightIcon = ChevronRight;
  InfoIcon = Info;

  // State Signals
  loading = signal<boolean>(true);
  errorMessage = signal<string | null>(null);
  successToast = signal<string | null>(null);

  summary = signal<IntentSummaryReport | null>(null);
  dossiers = signal<EntityIntentDossier[]>([]);
  selectedDossier = signal<EntityIntentDossier | null>(null);
  catalog = signal<any | null>(null);
  fleetAgents = signal<Agent[]>([]);

  // Filters & Tabs
  activeTab = signal<'dossier' | 'actions' | 'radar'>('dossier');
  filterIntent = signal<string>('ALL');
  searchQuery = signal<string>('');
  actionFilter = signal<'ALL' | 'pending' | 'executed'>('ALL');

  // Simulation Modal Signals
  showSimModal = signal<boolean>(false);
  simEvaluating = signal<boolean>(false);
  simProgress = signal<number>(0);
  simStageNumber = signal<number>(1);
  simCurrentStageText = signal<string>('');
  simCompleted = signal<boolean>(false);
  simResultPreview = signal<EntityIntentDossier | null>(null);

  selectedSimAgentId = signal<string>('custom');
  simAgentId = signal<string>('042');
  simAgentName = signal<string>('win-node-7a5e');
  simAgentIp = signal<string>('192.168.1.142');
  simTechniquesInput = signal<string>('T1190, T1059.001, T1003, T1490, T1486');
  simUser = signal<string>('administrator');
  simContext = signal<string>('Active ransomware staging indicators observed');

  // Action Execution State
  executingActionId = signal<string | null>(null);

  // Computed Properties
  filteredDossiers = computed(() => {
    let list = this.dossiers();
    const query = this.searchQuery().trim().toLowerCase();
    const intent = this.filterIntent();

    if (query) {
      list = list.filter(
        d =>
          d.entity_name.toLowerCase().includes(query) ||
          d.entity_ip.toLowerCase().includes(query) ||
          d.primary_intent.toLowerCase().includes(query)
      );
    }

    if (intent !== 'ALL') {
      list = list.filter(d => d.primary_intent.toUpperCase() === intent.toUpperCase());
    }

    return list;
  });

  allPreemptiveActions = computed(() => {
    const map = new Map<string, PreemptiveAction>();
    for (const d of this.dossiers()) {
      for (const a of d.recommended_actions) {
        map.set(a.id, a);
      }
    }
    const actions = Array.from(map.values());
    const filter = this.actionFilter();
    if (filter === 'pending') {
      return actions.filter(a => a.status === 'pending_approval');
    } else if (filter === 'executed') {
      return actions.filter(a => a.status === 'executed');
    }
    return actions;
  });

  ngOnInit() {
    this.refreshAll();
    this.loadFleetAgents();
  }

  loadFleetAgents() {
    this.siem.getAgents().subscribe({
      next: (agents) => {
        this.fleetAgents.set(agents);
        if (agents.length > 0 && this.selectedSimAgentId() === 'custom') {
          const first = agents[0];
          this.selectedSimAgentId.set(first.id);
          this.simAgentId.set(first.id);
          this.simAgentName.set(first.name);
          this.simAgentIp.set(first.ip);
          const isWin = first.os_type === 'windows' || first.name.toLowerCase().includes('win');
          this.simUser.set(isWin ? 'administrator' : 'root');
        }
      },
      error: (err) => console.warn('Failed to load fleet agents for intent prediction', err)
    });
  }

  refreshAll() {
    this.loading.set(true);
    this.errorMessage.set(null);

    // Check for target host in query parameter or session storage for persistence across refresh
    const targetHostId =
      this.route.snapshot.queryParamMap.get('host') ||
      sessionStorage.getItem('intent_selected_host');

    this.siem.getIntentSummary().subscribe({
      next: (sum) => {
        this.summary.set(sum);
        const list = sum.top_dossiers || [];
        this.dossiers.set(list);
        if (list.length > 0) {
          const match = targetHostId
            ? list.find(d => d.entity_id === targetHostId || d.id === targetHostId)
            : null;
          const chosen = match || list[0];
          this.selectedDossier.set(chosen);
          if (chosen) {
            sessionStorage.setItem('intent_selected_host', chosen.entity_id);
          }
        } else {
          this.selectedDossier.set(null);
        }
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Failed to load intent summary', err);
        this.errorMessage.set('Could not fetch intent hypotheses from API. Verify siem-api service is running.');
        this.loading.set(false);
      }
    });

    this.siem.getIntentCatalog().subscribe({
      next: (cat) => this.catalog.set(cat),
      error: (err) => console.warn('Catalog load issue', err)
    });
  }

  selectDossier(d: EntityIntentDossier) {
    this.selectedDossier.set(d);
    sessionStorage.setItem('intent_selected_host', d.entity_id);
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { host: d.entity_id },
      queryParamsHandling: 'merge'
    });
    this.activeTab.set('dossier');
  }

  executeAction(action: PreemptiveAction, dryRun = false) {
    this.executingActionId.set(action.id);
    const req: ExecuteActionRequest = {
      action_id: action.id,
      dry_run: dryRun
    };

    this.siem.executePreemptiveAction(req).subscribe({
      next: (updatedAction) => {
        this.executingActionId.set(null);
        this.triggerToast(`Countermeasure "${action.title}" executed successfully.`);
        
        // Update local state in dossier
        const currentSelected = this.selectedDossier();
        if (currentSelected) {
          const updatedActions = currentSelected.recommended_actions.map(a =>
            a.id === updatedAction.id ? updatedAction : a
          );
          this.selectedDossier.set({
            ...currentSelected,
            recommended_actions: updatedActions
          });
        }

        // Also update in dossiers array
        const updatedDossiers = this.dossiers().map(d => {
          return {
            ...d,
            recommended_actions: d.recommended_actions.map(a =>
              a.id === updatedAction.id ? updatedAction : a
            )
          };
        });
        this.dossiers.set(updatedDossiers);
      },
      error: (err) => {
        console.error('Failed to execute countermeasure', err);
        this.executingActionId.set(null);
        this.errorMessage.set(`Execution failed: ${err.message || 'Unknown error'}`);
      }
    });
  }

  availableAgents = computed(() => {
    const fleet = this.fleetAgents();
    if (fleet.length > 0) {
      return fleet.map(a => ({
        entity_id: a.id,
        entity_name: a.name,
        entity_ip: a.ip,
        os_type: a.os_type || (a.name.toLowerCase().includes('win') ? 'windows' : 'linux')
      }));
    }
    return this.dossiers().map(d => ({
      entity_id: d.entity_id,
      entity_name: d.entity_name,
      entity_ip: d.entity_ip,
      os_type: d.os_type
    }));
  });

  openSimulationModal() {
    this.simEvaluating.set(false);
    this.simProgress.set(0);
    this.simStageNumber.set(1);
    this.simCurrentStageText.set('');
    this.simCompleted.set(false);
    this.simResultPreview.set(null);

    const current = this.selectedDossier() || (this.dossiers().length > 0 ? this.dossiers()[0] : null);
    if (current) {
      this.selectedSimAgentId.set(current.entity_id);
      this.simAgentId.set(current.entity_id);
      this.simAgentName.set(current.entity_name);
      this.simAgentIp.set(current.entity_ip);
      const isWin = current.os_type === 'windows' || current.entity_name.toLowerCase().includes('win');
      this.simUser.set(isWin ? 'administrator' : 'root');
    } else {
      const fleet = this.fleetAgents();
      if (fleet.length > 0) {
        const first = fleet[0];
        this.selectedSimAgentId.set(first.id);
        this.simAgentId.set(first.id);
        this.simAgentName.set(first.name);
        this.simAgentIp.set(first.ip);
        const isWin = first.os_type === 'windows' || first.name.toLowerCase().includes('win');
        this.simUser.set(isWin ? 'administrator' : 'root');
      } else {
        this.selectedSimAgentId.set('custom');
        this.simAgentId.set('042');
        this.simAgentName.set('win-node-7a5e');
        this.simAgentIp.set('192.168.1.142');
        this.simUser.set('administrator');
      }
    }
    this.showSimModal.set(true);
  }

  onSelectSimAgent(event: Event) {
    const id = (event.target as HTMLSelectElement).value;
    this.selectedSimAgentId.set(id);
    if (id === 'custom') {
      this.simAgentId.set('sim-' + Math.floor(100 + Math.random() * 900));
      this.simAgentName.set('simulated-target-node');
      this.simAgentIp.set('192.168.1.188');
      this.simUser.set('administrator');
    } else {
      const fleetMatch = this.fleetAgents().find(a => a.id === id);
      if (fleetMatch) {
        this.simAgentId.set(fleetMatch.id);
        this.simAgentName.set(fleetMatch.name);
        this.simAgentIp.set(fleetMatch.ip);
        const isWin = fleetMatch.os_type === 'windows' || fleetMatch.name.toLowerCase().includes('win');
        this.simUser.set(isWin ? 'administrator' : 'root');
      } else {
        const dossierMatch = this.dossiers().find(d => d.entity_id === id);
        if (dossierMatch) {
          this.simAgentId.set(dossierMatch.entity_id);
          this.simAgentName.set(dossierMatch.entity_name);
          this.simAgentIp.set(dossierMatch.entity_ip);
          const isWin = dossierMatch.os_type === 'windows' || dossierMatch.entity_name.toLowerCase().includes('win');
          this.simUser.set(isWin ? 'administrator' : 'root');
        }
      }
    }
  }

  loadScenario(scenario: 'ransomware' | 'exfil' | 'ad_takeover' | 'wiper') {
    if (scenario === 'ransomware') {
      this.simTechniquesInput.set('T1190, T1059.001, T1003, T1490, T1486');
      this.simContext.set('Initial access via public exploit, credential dumping, shadow-copy wipe, and mass encryption staging.');
    } else if (scenario === 'exfil') {
      this.simTechniquesInput.set('T1190, T1003, T1560, T1048, T1041');
      this.simContext.set('Credential harvesting, multi-part archive creation, and covert outbound transmission over C2 channel.');
    } else if (scenario === 'ad_takeover') {
      this.simTechniquesInput.set('T1078, T1059.001, T1003, T1484, T1098');
      this.simContext.set('Compromised privileged credentials, domain policy tampering, and account elevation to Domain Admins.');
    } else if (scenario === 'wiper') {
      this.simTechniquesInput.set('T1059, T1485, T1561');
      this.simContext.set('Destructive disk wipe routines executing directly against storage volumes.');
    }
  }

  closeSimulationModal() {
    this.showSimModal.set(false);
  }

  submitSimulation() {
    const rawTechniques = this.simTechniquesInput()
      .split(',')
      .map(t => t.trim().toUpperCase())
      .filter(t => t.length > 0);

    const req: SimulationIntentRequest = {
      agent_id: this.simAgentId().trim() || 'sim-agent-001',
      agent_name: this.simAgentName().trim() || 'simulated-target-node',
      agent_ip: this.simAgentIp().trim() || '192.168.1.100',
      observed_techniques: rawTechniques,
      user: this.simUser().trim() || 'system',
      custom_context: this.simContext().trim() || undefined
    };

    this.simEvaluating.set(true);
    this.simCompleted.set(false);
    this.simProgress.set(15);
    this.simStageNumber.set(1);
    this.simCurrentStageText.set('Step 1/4: Ingesting MITRE techniques & mapping to 9-Stage Kill-Chain...');

    this.siem.evaluateIntentSimulation(req).subscribe({
      next: (evaluatedDossier) => {
        // Step through animated milestones so the analyst can clearly observe each calculation stage
        setTimeout(() => {
          this.simProgress.set(45);
          this.simStageNumber.set(2);
          this.simCurrentStageText.set('Step 2/4: Computing kill-chain velocity & lateral transition probability vectors...');
        }, 350);

        setTimeout(() => {
          this.simProgress.set(75);
          this.simStageNumber.set(3);
          this.simCurrentStageText.set('Step 3/4: Synthesizing Bayesian multi-hypothesis distribution across threat archetypes...');
        }, 700);

        setTimeout(() => {
          this.simProgress.set(100);
          this.simStageNumber.set(4);
          this.simCurrentStageText.set('Step 4/4: Formulating OS-tailored micro-containment response playbooks...');
          this.simEvaluating.set(false);
          this.simCompleted.set(true);
          this.simResultPreview.set(evaluatedDossier);
        }, 1100);
      },
      error: (err) => {
        this.simEvaluating.set(false);
        alert(`Simulation evaluation failed: ${err.message || 'Error occurred'}`);
      }
    });
  }

  applySimulationResult() {
    const evaluatedDossier = this.simResultPreview();
    if (!evaluatedDossier) {
      this.closeSimulationModal();
      return;
    }

    this.closeSimulationModal();
    this.triggerToast(`Intent projection generated for ${evaluatedDossier.entity_name}!`);

    // Prepend to dossiers and select
    const current = this.dossiers().filter(d => d.id !== evaluatedDossier.id && d.entity_id !== evaluatedDossier.entity_id);
    this.dossiers.set([evaluatedDossier, ...current]);
    this.selectedDossier.set(evaluatedDossier);
    sessionStorage.setItem('intent_selected_host', evaluatedDossier.entity_id);
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { host: evaluatedDossier.entity_id },
      queryParamsHandling: 'merge'
    });
    this.activeTab.set('dossier');
  }

  private triggerToast(msg: string) {
    this.successToast.set(msg);
    setTimeout(() => {
      if (this.successToast() === msg) {
        this.successToast.set(null);
      }
    }, 4000);
  }

  // Helpers
  getIntentClass(intent: string): string {
    switch (intent.toUpperCase()) {
      case 'RANSOMWARE':
        return 'intent-ransomware';
      case 'DATA_EXFILTRATION':
        return 'intent-exfil';
      case 'APT_ESPIONAGE':
        return 'intent-espionage';
      case 'DESTRUCTIVE_WIPER':
        return 'intent-wiper';
      case 'CRYPTOMINING':
        return 'intent-crypto';
      default:
        return 'intent-generic';
    }
  }

  getIntentLabel(intent: string): string {
    switch (intent.toUpperCase()) {
      case 'RANSOMWARE':
        return 'Ransomware Deployment';
      case 'DATA_EXFILTRATION':
        return 'Data Exfiltration';
      case 'APT_ESPIONAGE':
        return 'APT Espionage & Living-off-the-Land';
      case 'DESTRUCTIVE_WIPER':
        return 'Destructive Wiper / Sabotage';
      case 'CRYPTOMINING':
        return 'Unauthorized Cryptomining';
      default:
        return intent;
    }
  }

  getVelocityClass(velocity: string): string {
    switch (velocity.toLowerCase()) {
      case 'accelerating':
        return 'badge-velocity-danger';
      case 'steady':
        return 'badge-velocity-warning';
      case 'lurking':
        return 'badge-velocity-info';
      default:
        return 'badge-velocity-neutral';
    }
  }

  getMilestoneClass(status: string): string {
    switch (status) {
      case 'observed':
        return 'milestone-observed';
      case 'current':
        return 'milestone-current';
      case 'predicted_next':
        return 'milestone-predicted';
      default:
        return 'milestone-unreached';
    }
  }

  getUrgencyBadge(urgency: string): string {
    switch (urgency) {
      case 'Immediate':
        return 'badge-urgency-immediate';
      case 'Elevated':
        return 'badge-urgency-elevated';
      default:
        return 'badge-urgency-advisory';
    }
  }
}
