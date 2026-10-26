import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Sparkles,
  Key,
  FileCode,
  Radio,
  Server,
  Play,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ChevronRight,
  Plus,
  Terminal,
  Activity,
  Info
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  DeceptionAsset,
  DeceptionAssetType,
  AssetDeploymentStatus,
  TripwireEvent,
  DeceptionBlueprint,
  DeceptionSummary,
  CreateAssetRequest,
  SimulateTripwireRequest
} from '../../../services/siem/siem.models';

@Component({
  selector: 'app-deception',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './deception.html',
  styleUrl: './deception.css'
})
export class Deception implements OnInit {
  private siem = inject(SiemService);

  // Icons
  ShieldIcon = Shield;
  ShieldAlertIcon = ShieldAlert;
  ShieldCheckIcon = ShieldCheck;
  ZapIcon = Zap;
  SparklesIcon = Sparkles;
  KeyIcon = Key;
  FileCodeIcon = FileCode;
  RadioIcon = Radio;
  ServerIcon = Server;
  PlayIcon = Play;
  TrashIcon = Trash2;
  RefreshIcon = RefreshCw;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;
  ClockIcon = Clock;
  LayersIcon = Layers;
  ChevronRightIcon = ChevronRight;
  PlusIcon = Plus;
  TerminalIcon = Terminal;
  ActivityIcon = Activity;
  InfoIcon = Info;

  // State Signals
  loading = signal<boolean>(true);
  errorMessage = signal<string | null>(null);
  successToast = signal<string | null>(null);

  summary = signal<DeceptionSummary | null>(null);
  assets = signal<DeceptionAsset[]>([]);
  triggers = signal<TripwireEvent[]>([]);
  blueprints = signal<DeceptionBlueprint[]>([]);

  // Navigation & Filtering
  activeTab = signal<'assets' | 'triggers' | 'blueprints'>('assets');
  typeFilter = signal<string>('ALL');
  statusFilter = signal<string>('ALL');
  searchQuery = signal<string>('');

  // Deploy Modal Signals
  showDeployModal = signal<boolean>(false);
  deploying = signal<boolean>(false);
  formName = signal<string>('');
  formType = signal<DeceptionAssetType>('canary_file');
  formAgentId = signal<string>('001');
  formAgentName = signal<string>('srv-prod-ubuntu-01');
  formPath = signal<string>('/var/data/shared/vault_keys.json');
  formPayload = signal<string>('{\"canary_id\": \"CANARY_BREADCRUMB_AUTH_TOKEN\"}');
  formTags = signal<string>('canary, fim, credentials');

  // Trigger Simulation Modal Signals
  showTestModal = signal<boolean>(false);
  testing = signal<boolean>(false);
  selectedAssetForTest = signal<DeceptionAsset | null>(null);
  testAttackerIp = signal<string>('198.51.100.89');
  testAttackerUser = signal<string>('nt_authority\\system');
  testProcessName = signal<string>('powershell.exe');
  testTechnique = signal<string>('T1552');
  testNotes = signal<string>('Automated honeynet breadcrumb access detected by syscheck');

  // Computed Properties
  filteredAssets = computed(() => {
    let list = this.assets();
    const query = this.searchQuery().trim().toLowerCase();
    const type = this.typeFilter();
    const status = this.statusFilter();

    if (query) {
      list = list.filter(
        a =>
          a.name.toLowerCase().includes(query) ||
          a.target_agent_name.toLowerCase().includes(query) ||
          a.target_path_or_port.toLowerCase().includes(query) ||
          a.tags.some(t => t.toLowerCase().includes(query))
      );
    }

    if (type !== 'ALL') {
      list = list.filter(a => a.asset_type === type);
    }

    if (status !== 'ALL') {
      list = list.filter(a => a.status === status);
    }

    return list;
  });

  filteredTriggers = computed(() => {
    let list = this.triggers();
    const query = this.searchQuery().trim().toLowerCase();
    if (query) {
      list = list.filter(
        t =>
          t.asset_name.toLowerCase().includes(query) ||
          t.attacker_ip.toLowerCase().includes(query) ||
          t.agent_name.toLowerCase().includes(query) ||
          t.mitre_technique.toLowerCase().includes(query)
      );
    }
    return list;
  });

  ngOnInit() {
    this.refreshAll();
  }

  refreshAll() {
    this.loading.set(true);
    this.errorMessage.set(null);

    this.siem.getDeceptionSummary().subscribe({
      next: (sum) => {
        this.summary.set(sum);
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Failed to load deception summary', err);
        this.errorMessage.set('Could not fetch deception metrics. Verify siem-api is running.');
        this.loading.set(false);
      }
    });

    this.siem.getDeceptionAssets().subscribe({
      next: (data) => this.assets.set(data),
      error: (err) => console.warn('Assets load issue', err)
    });

    this.siem.getDeceptionTriggers().subscribe({
      next: (data) => this.triggers.set(data),
      error: (err) => console.warn('Triggers load issue', err)
    });

    this.siem.getDeceptionTemplates().subscribe({
      next: (data) => this.blueprints.set(data),
      error: (err) => console.warn('Blueprints load issue', err)
    });
  }

  openDeployModal(bp?: DeceptionBlueprint) {
    if (bp) {
      this.formName.set(`Decoy: ${bp.title}`);
      this.formType.set(bp.asset_type);
      this.formPath.set(bp.default_path);
      this.formPayload.set(bp.default_payload);
      this.formTags.set('deception, blueprint, canary');
    } else {
      this.formName.set('Custom Canary Tripwire File');
      this.formType.set('canary_file');
      this.formPath.set('/var/data/shared/master_creds.kdbx');
      this.formPayload.set('CANARY_BINARY_PAYLOAD_SIGNATURE');
      this.formTags.set('canary, custom');
    }
    this.showDeployModal.set(true);
  }

  closeDeployModal() {
    this.showDeployModal.set(false);
  }

  submitDeploy() {
    const rawTags = this.formTags()
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    const req: CreateAssetRequest = {
      name: this.formName().trim(),
      asset_type: this.formType(),
      target_agent_id: this.formAgentId().trim() || '001',
      target_agent_name: this.formAgentName().trim() || 'srv-prod-ubuntu-01',
      target_path_or_port: this.formPath().trim(),
      decoy_payload_preview: this.formPayload().trim(),
      tags: rawTags.length > 0 ? rawTags : undefined,
    };

    this.deploying.set(true);
    this.siem.createDeceptionAsset(req).subscribe({
      next: (created) => {
        this.deploying.set(false);
        this.closeDeployModal();
        this.triggerToast(`Deception asset "${created.name}" successfully deployed and armed.`);
        this.assets.set([created, ...this.assets()]);
        this.refreshSummary();
      },
      error: (err) => {
        this.deploying.set(false);
        alert(`Failed to deploy asset: ${err.message || 'Error occurred'}`);
      }
    });
  }

  deleteAsset(asset: DeceptionAsset) {
    if (!confirm(`Are you sure you want to decommission and remove decoy "${asset.name}"?`)) {
      return;
    }

    this.siem.deleteDeceptionAsset(asset.id).subscribe({
      next: () => {
        this.triggerToast(`Deception asset "${asset.name}" decommissioned.`);
        this.assets.set(this.assets().filter(a => a.id !== asset.id));
        this.refreshSummary();
      },
      error: (err) => {
        console.error('Delete error', err);
        alert(`Failed to remove asset: ${err.message || 'Error'}`);
      }
    });
  }

  openTestModal(asset: DeceptionAsset) {
    this.selectedAssetForTest.set(asset);
    this.testTechnique.set(
      asset.asset_type === 'honeytoken_credential' ? 'T1078' :
      asset.asset_type === 'decoy_network_service' ? 'T1046' : 'T1552'
    );
    this.showTestModal.set(true);
  }

  closeTestModal() {
    this.showTestModal.set(false);
    this.selectedAssetForTest.set(null);
  }

  submitTestTrigger() {
    const asset = this.selectedAssetForTest();
    if (!asset) return;

    const req: SimulateTripwireRequest = {
      asset_id: asset.id,
      attacker_ip: this.testAttackerIp().trim(),
      attacker_user: this.testAttackerUser().trim(),
      process_name: this.testProcessName().trim(),
      mitre_technique: this.testTechnique().trim(),
      notes: this.testNotes().trim(),
    };

    this.testing.set(true);
    this.siem.simulateDeceptionTripwire(req).subscribe({
      next: (event) => {
        this.testing.set(false);
        this.closeTestModal();
        this.triggerToast(`Tripwire tripped! High-fidelity incident recorded for ${asset.name}.`);
        this.triggers.set([event, ...this.triggers()]);
        
        // Update asset status
        const updatedAssets = this.assets().map(a => {
          if (a.id === asset.id) {
            return {
              ...a,
              status: 'triggered' as AssetDeploymentStatus,
              tripped_count: a.tripped_count + 1,
              last_tripped_at: event.timestamp
            };
          }
          return a;
        });
        this.assets.set(updatedAssets);
        this.refreshSummary();
        this.activeTab.set('triggers');
      },
      error: (err) => {
        this.testing.set(false);
        alert(`Tripwire test failed: ${err.message || 'Error'}`);
      }
    });
  }

  private refreshSummary() {
    this.siem.getDeceptionSummary().subscribe({
      next: (sum) => this.summary.set(sum),
      error: (e) => console.warn('Summary update error', e)
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

  // Visual Helpers
  getAssetTypeLabel(type: string): string {
    switch (type) {
      case 'canary_file': return 'Canary File / Document';
      case 'honeytoken_credential': return 'Honeytoken API / Credential';
      case 'decoy_network_service': return 'Decoy Port / Ghost Service';
      case 'canary_registry_key': return 'Canary Registry Key';
      case 'active_directory_decoy': return 'Decoy AD Account / SPN';
      default: return type;
    }
  }

  getAssetTypeBadge(type: string): string {
    switch (type) {
      case 'honeytoken_credential': return 'badge-type-token';
      case 'canary_file': return 'badge-type-file';
      case 'decoy_network_service': return 'badge-type-service';
      case 'active_directory_decoy': return 'badge-type-ad';
      default: return 'badge-type-default';
    }
  }

  getStatusBadge(status: string): string {
    switch (status) {
      case 'armed': return 'status-armed';
      case 'triggered': return 'status-triggered';
      case 'decommissioned': return 'status-decommissioned';
      default: return 'status-pending';
    }
  }
}
