import { Component, Input, OnInit, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  ShieldCheck, Activity, Bot,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { TrustedDomainsBase } from '../../shared/trusted-domains/trusted-domains-base';

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
  @Input() tenantId = '';

  ShieldIcon   = ShieldCheck;
  ActivityIcon = Activity;
  BotIcon      = Bot;

  /** Alias matching this page's own naming — same computed as the base's tenantDomains. */
  readonly tenantOwnDomains = this.tenantDomains;

  constructor(api: Api, private auth: AuthService) {
    super(api);
  }

  override ngOnInit(): void {
    if (!this.tenantId) {
      this.tenantId = this.auth.getUser()?.tenant_id || 'default';
    }
    super.ngOnInit();
  }

  protected override filterAiSuggestions(suggestions: any[]): any[] {
    return suggestions.filter((s: any) => s.verdict === 'TRUSTED');
  }
}
