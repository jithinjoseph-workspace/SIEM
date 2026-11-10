import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  RefreshCw, ShieldCheck, Trash2, Clock, Activity, Layers, CheckCircle2, AlertTriangle, Search, Check, X, ShieldAlert, Building2
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';
import { TrustedDomainsBase } from '../../shared/trusted-domains/trusted-domains-base';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-trusted-domains',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './trusted-domains.html',
  styleUrl: './trusted-domains.css',
})
export class TrustedDomains extends TrustedDomainsBase implements OnInit {
  Math = Math;

  RefreshIcon     = RefreshCw;
  ShieldIcon      = ShieldCheck;
  TrashIcon       = Trash2;
  ClockIcon       = Clock;
  ActivityIcon    = Activity;
  LayersIcon      = Layers;
  CheckIcon       = CheckCircle2;
  AlertIcon       = AlertTriangle;
  SearchIcon      = Search;
  ApproveIcon     = Check;
  DismissIcon     = X;
  ShieldAlertIcon = ShieldAlert;
  BuildingIcon    = Building2;

  readonly tenants = signal<any[]>([]);

  domainSearch = '';
  scopeFilter  = 'all'; // 'all' | 'global' | 'tenant'

  constructor(api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {
    super(api);
  }

  get beaconCategoryCount(): number {
    return this.trustedDomains().filter(d => d.category === 'dns_beacon').length;
  }

  get threatIntelCategoryCount(): number {
    return this.trustedDomains().filter(d => d.category === 'threat_intel').length;
  }

  get filteredDomains(): any[] {
    const q = this.domainSearch.trim().toLowerCase();
    return this.trustedDomains().filter(d => {
      const matchesSearch = !q ||
        d.domain?.toLowerCase().includes(q) ||
        d.note?.toLowerCase().includes(q) ||
        d.category?.toLowerCase().includes(q);
      const matchesScope = this.scopeFilter === 'all' || d.scope === this.scopeFilter;
      return matchesSearch && matchesScope;
    });
  }

  tenantName(tenantId: string): string {
    const t = this.tenants().find(x => x.id === tenantId);
    return t ? t.name : (tenantId || 'Default Organization');
  }

  override ngOnInit(): void {
    super.ngOnInit();
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants.set(data.tenants || []); this.cdr.detectChanges(); },
      error: reportRxjsError,
    });
  }
}
