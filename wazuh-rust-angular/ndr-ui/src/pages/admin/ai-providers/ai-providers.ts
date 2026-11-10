import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Edit, Eye, EyeOff, LoaderCircle, Plus, Save, Trash2, X, Zap,
  Sparkles, Bot, ShieldCheck, KeyRound, Cpu, Activity, Clock, RefreshCw, Layers, CheckCircle2, AlertTriangle, SlidersHorizontal
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';

interface AiProvider {
  name: string; provider_type: string; model: string; base_url: string;
  endpoint_path: string; msg_format: string; use_case: string;
  priority: number; enabled: boolean; key_set: boolean;
}

@Component({
  selector: 'app-ai-providers',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './ai-providers.html',
  styleUrl: './ai-providers.css',
})
export class AiProviders implements OnInit {
  Math = Math;

  EditIcon        = Edit;
  EyeIcon         = Eye;
  EyeOffIcon      = EyeOff;
  LoadingIcon     = LoaderCircle;
  PlusIcon        = Plus;
  SaveIcon        = Save;
  TrashIcon       = Trash2;
  TestIcon        = Zap;
  XIcon           = X;
  SparklesIcon    = Sparkles;
  BotIcon         = Bot;
  ShieldCheckIcon = ShieldCheck;
  KeyRoundIcon    = KeyRound;
  CpuIcon         = Cpu;
  ActivityIcon    = Activity;
  ClockIcon       = Clock;
  RefreshIcon     = RefreshCw;
  LayersIcon      = Layers;
  CheckIcon       = CheckCircle2;
  AlertIcon       = AlertTriangle;
  SlidersIcon     = SlidersHorizontal;

  providers: AiProvider[] = [];
  loadingProviders  = false;
  savingProvider    = false;
  providerMessage   = '';
  providerError     = '';
  testProviderResult = '';
  showAddProviderForm = false;
  testingProvider   = '';
  showProviderKey   = false;
  isEditingProvider = false;

  newProvider = {
    name: '', provider_type: 'custom', api_key: '', model: '',
    base_url: '', endpoint_path: '/v1/chat/completions',
    msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
  };

  providerTypeOptions = [
    { value: 'custom',    label: 'Custom / OpenAI-compatible' },
    { value: 'openai',    label: 'OpenAI' },
    { value: 'anthropic', label: 'Anthropic' },
  ];
  useCaseOptions = [
    { value: 'all',    label: 'All (chat + threat analysis)' },
    { value: 'chat',   label: 'ARIA chat only' },
    { value: 'threat', label: 'Threat analysis only' },
  ];

  constructor(private api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {}

  get activeProvidersCount(): number {
    return this.providers.filter(p => p.enabled).length;
  }

  get activeRatio(): number {
    if (!this.providers.length) return 0;
    return Math.round((this.activeProvidersCount / this.providers.length) * 100);
  }

  get keySetCount(): number {
    return this.providers.filter(p => p.key_set).length;
  }

  get chatProvidersCount(): number {
    return this.providers.filter(p => p.enabled && (p.use_case === 'all' || p.use_case === 'chat')).length;
  }

  get threatProvidersCount(): number {
    return this.providers.filter(p => p.enabled && (p.use_case === 'all' || p.use_case === 'threat')).length;
  }

  get primaryProvider(): AiProvider | null {
    const active = this.providers.filter(p => p.enabled);
    if (!active.length) return null;
    return [...active].sort((a, b) => (a.priority || 99) - (b.priority || 99))[0];
  }

  ngOnInit() {
    this.loadProviders();
  }

  loadProviders() {
    this.loadingProviders = true;
    this.api.listAiProviders().subscribe({
      next: (data: any) => { this.providers = data.providers || []; this.loadingProviders = false; this.cdr.detectChanges(); },
      error: () => { this.loadingProviders = false; this.cdr.detectChanges(); },
    });
  }

  saveProvider() {
    this.savingProvider = true;
    this.providerMessage = ''; this.providerError = '';
    this.api.saveAiProvider(this.newProvider).subscribe({
      next: () => {
        this.savingProvider = false;
        this.providerMessage = `Provider "${this.newProvider.name}" saved`;
        this.showAddProviderForm = false;
        this.resetNewProvider();
        this.loadProviders();
        this.cdr.detectChanges();
        setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: () => { this.savingProvider = false; this.providerError = 'Failed to save provider'; this.cdr.detectChanges(); },
    });
  }

  deleteProvider(name: string) {
    if (!confirm(`Delete provider "${name}"?`)) return;
    this.api.deleteAiProvider(name).subscribe({
      next: () => {
        this.providerMessage = `Provider "${name}" deleted`;
        this.loadProviders(); this.cdr.detectChanges();
        setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: () => { this.providerError = 'Failed to delete provider'; this.cdr.detectChanges(); },
    });
  }

  testProvider(p: AiProvider) {
    this.testingProvider = p.name; this.testProviderResult = '';
    const payload = {
      name: p.name, provider_type: p.provider_type, api_key: '', model: p.model,
      base_url: p.base_url, endpoint_path: p.endpoint_path || '/v1/chat/completions', msg_format: p.msg_format || 'openai',
    };
    this.api.testAiProvider(payload).subscribe({
      next: (data: any) => {
        this.testingProvider = '';
        this.testProviderResult = data.status === 'ok' ? `✓ ${p.name} — OK` : `✗ ${p.name} — ${data.error}`;
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 5000);
      },
      error: () => {
        this.testingProvider = ''; this.testProviderResult = `✗ ${p.name} — request failed`;
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 5000);
      },
    });
  }

  testNewProvider() {
    this.testingProvider = '__new__'; this.testProviderResult = '';
    this.api.testAiProvider(this.newProvider).subscribe({
      next: (data: any) => {
        this.testingProvider = '';
        this.testProviderResult = data.status === 'ok'
          ? '✓ Connection OK — ' + (data.response || '').substring(0, 60)
          : '✗ ' + (data.error || 'No response');
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 6000);
      },
      error: () => {
        this.testingProvider = ''; this.testProviderResult = '✗ Request failed — check URL and key';
        this.cdr.detectChanges();
      },
    });
  }

  resetNewProvider() {
    this.isEditingProvider = false;
    this.newProvider = {
      name: '', provider_type: 'custom', api_key: '', model: '',
      base_url: '', endpoint_path: '/v1/chat/completions',
      msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
    };
  }

  editProvider(p: AiProvider) {
    this.isEditingProvider = true;
    this.newProvider = { ...p, api_key: '' };
    this.showAddProviderForm = true;
  }

  get defaultBaseUrl(): string {
    switch (this.newProvider.provider_type) {
      case 'openai':    return 'https://api.openai.com';
      case 'anthropic': return 'https://api.anthropic.com';
      default:          return '';
    }
  }

  get defaultModelPlaceholder(): string {
    switch (this.newProvider.provider_type) {
      case 'openai':    return 'gpt-4o-mini';
      case 'anthropic': return 'claude-sonnet-4-6';
      default:          return 'e.g. llama-3.3-70b-versatile';
    }
  }

  useCaseLabel(uc: string): string {
    return ({ all: 'All', chat: 'Chat', threat: 'Threat' } as any)[uc] || uc;
  }
}
