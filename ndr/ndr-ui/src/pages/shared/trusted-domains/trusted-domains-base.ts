import { Directive, OnInit, signal, computed } from '@angular/core';
import { Globe, Plus, Sparkles } from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { reportRxjsError } from '../../../services/error-reporter/error-reporter';

/**
 * Shared state/logic for the admin (all-tenant) and tenant-admin (own-tenant)
 * trusted-domains pages. The backend (list_trusted_domains) already scopes
 * results by caller role — a tenant_admin only ever gets back global rows
 * plus their own tenant's rows — so the same filter/add/delete logic here
 * produces the right result for either role without needing to know which
 * one it's running as. Templates stay separate per role (the two designs
 * are intentionally different, not copy-pasted), only the .ts logic is shared.
 */
@Directive()
export abstract class TrustedDomainsBase implements OnInit {
  GlobeIcon    = Globe;
  PlusIcon     = Plus;
  SparklesIcon = Sparkles;

  readonly trustedDomains        = signal<any[]>([]);
  readonly loadingTrustedDomains = signal(false);
  readonly tdNewDomain           = signal('');
  readonly tdNewCategory         = signal('dns_beacon');
  /** '' = global; a tenant_id otherwise. Ignored server-side for non-super_admin callers. */
  readonly tdNewScope            = signal('');
  readonly tdNewNote             = signal('');
  readonly tdSaving              = signal(false);
  readonly tdAiLoading           = signal(false);
  readonly tdAiAvailable         = signal<boolean | null>(null);
  readonly tdAiSuggestions       = signal<any[]>([]);

  readonly globalDomains = computed(() => this.trustedDomains().filter(d => d.scope === 'global'));
  readonly tenantDomains = computed(() => this.trustedDomains().filter(d => d.scope === 'tenant'));

  constructor(protected api: Api) {}

  ngOnInit(): void {
    this.loadTrustedDomains();
  }

  trackByIndex(i: number): number {
    return i;
  }

  loadTrustedDomains(): void {
    this.loadingTrustedDomains.set(true);
    this.api.listTrustedDomains().subscribe({
      next: (data: any) => {
        this.trustedDomains.set(data.domains || []);
        this.loadingTrustedDomains.set(false);
      },
      error: () => { this.loadingTrustedDomains.set(false); },
    });
  }

  addTrustedDomain(): void {
    const d = this.tdNewDomain().trim().toLowerCase();
    if (!d) return;
    this.tdSaving.set(true);
    this.api.addTrustedDomain(d, this.tdNewCategory(), this.tdNewScope(), this.tdNewNote()).subscribe({
      next: () => {
        this.tdNewDomain.set('');
        this.tdNewNote.set('');
        this.tdSaving.set(false);
        this.loadTrustedDomains();
      },
      error: () => { this.tdSaving.set(false); },
    });
  }

  deleteTrustedDomain(domain: string, tenantId: string): void {
    this.api.deleteTrustedDomain(domain, tenantId).subscribe({
      next: () => {
        this.trustedDomains.update(list =>
          list.filter(d => !(d.domain === domain && d.tenant_id === tenantId))
        );
      },
      error: reportRxjsError,
    });
  }

  runAiSuggest(): void {
    this.tdAiLoading.set(true);
    this.tdAiSuggestions.set([]);
    this.api.aiSuggestTrustedDomains().subscribe({
      next: (data: any) => {
        this.tdAiAvailable.set(data.ai_available !== false);
        this.tdAiSuggestions.set(this.filterAiSuggestions(data.suggestions || []));
        this.tdAiLoading.set(false);
      },
      error: () => { this.tdAiLoading.set(false); },
    });
  }

  /** Override to narrow which AI suggestions are shown — the tenant view
   *  only ever surfaces TRUSTED verdicts, the admin view shows all of them
   *  with a visual TRUSTED/suspicious distinction instead. */
  protected filterAiSuggestions(suggestions: any[]): any[] {
    return suggestions;
  }

  approveTdSuggestion(s: any): void {
    this.api.addTrustedDomain(s.domain, 'dns_beacon', '', s.reason || '').subscribe({
      next: () => {
        this.tdAiSuggestions.update(list => list.filter(x => x.domain !== s.domain));
        this.loadTrustedDomains();
      },
      error: reportRxjsError,
    });
  }

  dismissTdSuggestion(domain: string): void {
    this.tdAiSuggestions.update(list => list.filter(s => s.domain !== domain));
  }
}
