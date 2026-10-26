import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
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
  KillChainMilestone
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

  // Filters & Tabs
  activeTab = signal<'dossier' | 'actions' | 'radar'>('dossier');
  filterIntent = signal<string>('ALL');
  searchQuery = signal<string>('');
  actionFilter = signal<'ALL' | 'pending' | 'executed'>('ALL');

  // Simulation Modal Signals
  showSimModal = signal<boolean>(false);
  simEvaluating = signal<boolean>(false);
  simAgentId = signal<string>('agent-089');
  simAgentName = signal<string>('fin-db-vault-prod');
  simAgentIp = signal<string>('172.16.88.42');
  simTechniquesInput = signal<string>('T1190, T1059, T1078, T1003, T1486');
  simUser = signal<string>('nt_authority\\system');
  simContext = signal<string>('Suspicious high-volume SMB staging and volume shadow copy access detected');

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
  }

  refreshAll() {
    this.loading.set(true);
    this.errorMessage.set(null);

    this.siem.getIntentSummary().subscribe({
      next: (sum) => {
        this.summary.set(sum);
        this.dossiers.set(sum.top_dossiers || []);
        if (sum.top_dossiers && sum.top_dossiers.length > 0 && !this.selectedDossier()) {
          this.selectedDossier.set(sum.top_dossiers[0]);
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

  openSimulationModal() {
    this.showSimModal.set(true);
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
    this.siem.evaluateIntentSimulation(req).subscribe({
      next: (evaluatedDossier) => {
        this.simEvaluating.set(false);
        this.closeSimulationModal();
        this.triggerToast(`Intent projection generated for ${evaluatedDossier.entity_name}!`);

        // Prepend to dossiers and select
        const current = this.dossiers().filter(d => d.id !== evaluatedDossier.id);
        this.dossiers.set([evaluatedDossier, ...current]);
        this.selectedDossier.set(evaluatedDossier);
        this.activeTab.set('dossier');
      },
      error: (err) => {
        this.simEvaluating.set(false);
        alert(`Simulation evaluation failed: ${err.message || 'Error occurred'}`);
      }
    });
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
