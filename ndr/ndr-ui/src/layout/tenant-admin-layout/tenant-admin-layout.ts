import {
  Component, OnInit, ChangeDetectionStrategy,
  signal, ViewEncapsulation, WritableSignal,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import {
  LucideAngularModule,
  Users, Globe, Activity, User, Settings, HelpCircle,
  Building2, ArrowUpCircle, RefreshCw, Loader, ShieldCheck, X, Radio,
  ChevronDown, Cpu, Sliders,
} from 'lucide-angular';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { TenantStatusService } from '../../services/tenant-status/tenant-status';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';

import { reportRxjsError } from '../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-tenant-admin-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './tenant-admin-layout.html',
  styleUrls: [
    './tenant-admin-layout.css',
    '../../pages/tenant-admin/tenant-admin.css',
  ],
})
export class TenantAdminLayout implements OnInit {
  UsersIcon         = Users;
  GlobeIcon         = Globe;
  ActivityIcon      = Activity;
  UserIcon          = User;
  SettingsIcon      = Settings;
  HelpCircleIcon    = HelpCircle;
  BuildingIcon      = Building2;
  RadioIcon         = Radio;
  ChevronIcon       = ChevronDown;
  CpuIcon           = Cpu;
  SlidersIcon       = Sliders;

  groups: Record<string, boolean> = {
    identity: true,
    defense:  true,
    ops:      true,
  };

  toggleGroup(name: string) {
    this.groups[name] = !this.groups[name];
  }

  hasSiem = false;
  ArrowUpCircleIcon = ArrowUpCircle;
  RefreshCwIcon     = RefreshCw;
  LoaderIcon        = Loader;
  ShieldIcon        = ShieldCheck;
  XIcon             = X;

  readonly tenantId   = signal('');
  readonly tenantName = signal('Organization');

  // Shared poll (also used by the navbar) — see TenantStatusService.
  // Assigned in the constructor body, not as a field initializer: field
  // initializers can run before constructor-injected properties are set.
  readonly tenantSystemStatus: WritableSignal<'OPERATIONAL' | 'DEGRADED' | 'CHECKING...'>;

  readonly updateAvailable  = signal(false);
  readonly currentVersion   = signal('');
  readonly latestVersion    = signal('');
  readonly showUpdateDialog = signal(false);
  readonly updateApplying   = signal(false);
  readonly updateMessage    = signal('');
  readonly message          = signal('');
  readonly messageType      = signal<'success' | 'error'>('success');

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
    private tenantStatusService: TenantStatusService,
  ) {
    this.tenantSystemStatus = this.tenantStatusService.status;
  }

  ngOnInit() {
    const user = this.auth.getUser() || {};
    this.tenantId.set(user.tenant_id || 'default');
    this.tenantName.set(this.formatTenantName(user.tenant_id || 'default'));

    if (!['admin', 'super_admin', 'tenant_admin'].includes(user.role)) {
      this.router.navigate(['/dashboard']);
      return;
    }

    // SIEM nav section temporarily hidden — not needed right now.
    // Restore `this.auth.hasFeature('siem')` here to bring it back.
    this.hasSiem = false;
    // Idempotent — no-ops if the navbar (or a prior mount of this layout)
    // already started it. Shared for the whole session, not torn down in
    // ngOnDestroy below, since the navbar depends on it too.
    this.tenantStatusService.startPolling();
    this.checkForUpdates();
  }

  checkForUpdates() {
    this.api.getVersionStatus().subscribe({
      next: (data: any) => {
        this.currentVersion.set(data.current_version || '');
        this.latestVersion.set(data.latest_version  || '');
        this.updateAvailable.set(!!data.update_available);
      },
      error: reportRxjsError
    });
  }

  openUpdateDialog()  { this.showUpdateDialog.set(true); this.updateMessage.set(''); }
  closeUpdateDialog() { this.showUpdateDialog.set(false); }

  confirmApplyUpdate() {
    this.updateApplying.set(true);
    this.updateMessage.set('');

    this.tenantStatusService.stopPolling();
    const resumePolling = () => this.tenantStatusService.startPolling();

    this.api.applyUpdate().subscribe({
      next: (data: any) => {
        this.updateMessage.set(data.message || 'Update triggered. Services restarting…');
        this.updateApplying.set(false);
        this.updateAvailable.set(false);

        let attempts = 0;
        let pendingSub: Subscription | null = null;
        const poll = setInterval(() => {
          if (pendingSub) { pendingSub.unsubscribe(); pendingSub = null; }
          pendingSub = this.api.getVersionStatus().subscribe({
            next: (v: any) => {
              if (v.current_version === this.latestVersion() || ++attempts > 36) {
                clearInterval(poll);
                pendingSub = null;
                this.currentVersion.set(v.current_version);
                this.latestVersion.set(v.latest_version || '');
                this.updateAvailable.set(!!v.update_available);
                this.showUpdateDialog.set(false);
                this.showMessage(`Updated to v${v.current_version}`, 'success');
                resumePolling();
              }
            },
            error: () => { attempts++; }
          });
        }, 5000);
      },
      error: (err: any) => {
        this.updateMessage.set(err?.error?.message || 'Update request failed');
        this.updateApplying.set(false);
        resumePolling();
      }
    });
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
  }

  private formatTenantName(tenantId: string) {
    return tenantId.split(/[-_]/).filter(Boolean)
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ') || 'Organization';
  }
}
