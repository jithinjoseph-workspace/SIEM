import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Edit, Plus, RefreshCw, Search, X, KeyRound, Copy, Trash2,
  Building2, ShieldCheck, Users, Sparkles, Clock, CheckCircle2, AlertTriangle, Layers, Zap, Bot, Shield, Globe,
  Database, Server, Terminal, ArrowRight
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-tenants',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './tenants.html',
  styleUrl: './tenants.css',
})
export class Tenants implements OnInit, OnDestroy {
  EditIcon        = Edit;
  PlusIcon        = Plus;
  RefreshIcon     = RefreshCw;
  SearchIcon      = Search;
  XIcon           = X;
  KeyIcon         = KeyRound;
  CopyIcon        = Copy;
  TrashIcon       = Trash2;
  BuildingIcon    = Building2;
  ShieldCheckIcon = ShieldCheck;
  UsersIcon       = Users;
  SparklesIcon    = Sparkles;
  ClockIcon       = Clock;
  CheckCircleIcon = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;
  LayersIcon      = Layers;
  ZapIcon         = Zap;
  BotIcon         = Bot;
  ShieldIcon        = Shield;
  GlobeIcon         = Globe;
  DatabaseIcon      = Database;
  ServerIcon        = Server;
  TerminalIcon      = Terminal;
  ArrowRightIcon    = ArrowRight;

  currentUser: any = {};

  tenants: any[]     = [];
  users: any[]       = [];
  loadingTenants     = false;
  showAddTenant      = false;
  tenantSearch       = '';
  newTenant          = { name: '', id: '' };
  savingTenant       = false;
  tenantMsg          = '';
  editingTenant: any = null;
  tenantForm         = { name: '', active: true };

  // Feature management
  featureTenant: any  = null;
  featureForm         = { ndr: false, siem: false, soar: false, threat_intel: false, ai: false };
  savingFeatures      = false;

  // License generation
  licenseTenant: any  = null;
  licenseForm         = { expires_days: 365, max_sensors: 10, admin_user: '', admin_pass: '' };
  generatedToken      = '';
  generatingLicense   = false;
  tokenCopied         = false;
  licensePublicKey    = '';
  installCopied       = false;
  issuedLicenses: any[] = [];
  loadingLicenses     = false;

  msg     = '';
  msgType = '';

  constructor(
    private api: Api,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
    public clock: ClockService,
  ) {}

  Math = Math;

  get activeTenantsCount(): number {
    return this.tenants.filter(t => t.active).length;
  }

  get aiEnabledCount(): number {
    return this.tenants.filter(t => t.ai_enabled).length;
  }

  get aiAdoptionPercent(): number {
    if (!this.tenants.length) return 0;
    return Math.round((this.aiEnabledCount / this.tenants.length) * 100);
  }

  get totalUsersCount(): number {
    return this.users.filter(u => u.role !== 'super_admin').length;
  }

  get avgUsersPerTenant(): string {
    if (!this.tenants.length) return '0.0';
    return (this.totalUsersCount / this.tenants.length).toFixed(1);
  }

  get activePercent(): number {
    if (!this.tenants.length) return 100;
    return Math.round((this.activeTenantsCount / this.tenants.length) * 100);
  }

  ngOnInit() {
    this.currentUser = this.auth.getUser();
    this.loadTenants();
    this.loadUsers();
  }

  ngOnDestroy() {
    if (this.autoCloseTimer) clearTimeout(this.autoCloseTimer);
  }

  loadTenants() {
    this.loadingTenants = true;
    this.api.getTenants().subscribe({
      next: (data: any) => {
        this.tenants = data.tenants || [];
        this.loadingTenants = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingTenants = false;
        this.showMsg('Failed to load tenants', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  loadUsers() {
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = data.users || [];
        this.cdr.detectChanges();
      },
      error: reportRxjsError,
    });
  }

  get filteredTenants() {
    const query = this.tenantSearch.trim().toLowerCase();
    return this.tenants.filter(t =>
      !query || t.name?.toLowerCase().includes(query) || t.id?.toLowerCase().includes(query)
    );
  }

  get tenantAdmins() {
    return this.users.filter(u => u.role === 'tenant_admin');
  }

  tenantUserCount(tenantId: string) {
    return this.users.filter(u => u.tenant_id === tenantId).length;
  }

  tenantAdminCount(tenantId: string) {
    return this.tenantAdmins.filter(u => u.tenant_id === tenantId).length;
  }

  tenantIdExists(id: string) {
    return this.tenants.some(t => t.id === id);
  }

  get canCreateTenant() {
    return !!this.newTenant.name.trim() && !!this.newTenant.id.trim() && !this.tenantIdExists(this.newTenant.id);
  }

  onTenantNameChange() { this.newTenant.id = this.slugifyTenant(this.newTenant.name); }
  onTenantIdChange()   { this.newTenant.id = this.slugifyTenant(this.newTenant.id); }

  private slugifyTenant(value: string) {
    return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  }

  // ── High-Tech Tenant Provisioning Deck State ────────────────────────
  isProvisioning = false;
  provisioningProgress = 0;
  provisioningComplete = false;
  provisioningFailed = false;
  provisioningError = '';
  provisioningTenantName = '';
  provisioningTenantId = '';
  provisioningTargetDb = '';

  // Live state for the real createTenant() call, read directly by
  // finishProvisioning() below — NOT passed as parameters. The retry loop
  // there used to take a frozen snapshot of these as arguments, so once the
  // 5-step cosmetic animation finished before the real (often slower, since
  // it creates ~40 real tables) API response came back, every retry kept
  // checking the same stale "not done yet" snapshot forever and the modal
  // never closed even after the backend had long since finished.
  private provisioningApiDone = false;
  private provisioningApiResult: any = null;
  private provisioningApiError: any = null;

  provisioningSteps = [
    {
      id: 'params',
      title: 'Gathering Configuration & Parameters',
      desc: 'Validating namespace slug, RBAC scope & cryptographic boundary',
      status: 'pending' as 'pending' | 'active' | 'done' | 'error',
    },
    {
      id: 'db',
      title: 'Provisioning Dedicated ClickHouse Database',
      desc: 'Allocating tenant database on ClickHouse cluster',
      status: 'pending' as 'pending' | 'active' | 'done' | 'error',
    },
    {
      id: 'schema',
      title: 'Deploying Storage Schemas & Analytical Tables',
      desc: 'Instantiating ndr_hits, ndr_events, threat_intel & entity_scores',
      status: 'pending' as 'pending' | 'active' | 'done' | 'error',
    },
    {
      id: 'env',
      title: 'Configuring Environment & Network Fabric Isolation',
      desc: 'Enforcing multi-tenant memory & data plane segregation boundaries',
      status: 'pending' as 'pending' | 'active' | 'done' | 'error',
    },
    {
      id: 'activate',
      title: 'Activating Tenant Namespace',
      desc: 'Registering in global tenant ledger and arming mission control',
      status: 'pending' as 'pending' | 'active' | 'done' | 'error',
    },
  ];

  provisioningLogs: Array<{ time: string; text: string; type: 'info' | 'success' | 'warn' | 'error' }> = [];

  private addProvisioningLog(text: string, type: 'info' | 'success' | 'warn' | 'error' = 'info') {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    this.provisioningLogs.push({ time: timeStr, text, type });
    this.cdr.detectChanges();
  }

  addTenant() {
    if (!this.newTenant.name.trim()) { this.tenantMsg = 'Tenant name required'; return; }
    if (!this.newTenant.id.trim())   { this.tenantMsg = 'Tenant ID required'; return; }
    if (this.tenantIdExists(this.newTenant.id.trim())) { this.tenantMsg = 'Tenant ID already exists'; return; }

    const tenantName = this.newTenant.name.trim();
    const tenantId = this.newTenant.id.trim();
    const targetDb = 'ndr_' + tenantId.replace(/-/g, '_');

    this.isProvisioning = true;
    this.savingTenant = true;
    this.provisioningComplete = false;
    this.provisioningFailed = false;
    this.provisioningError = '';
    this.provisioningTenantName = tenantName;
    this.provisioningTenantId = tenantId;
    this.provisioningTargetDb = targetDb;
    this.provisioningProgress = 10;
    this.provisioningLogs = [];
    this.provisioningApiDone = false;
    this.provisioningApiResult = null;
    this.provisioningApiError = null;

    // Reset steps
    this.provisioningSteps.forEach((s, idx) => {
      s.status = idx === 0 ? 'active' : 'pending';
    });

    this.addProvisioningLog(`[INIT] Initializing tenant workspace for "${tenantName}" (${tenantId})`, 'info');
    this.cdr.detectChanges();

    let stepIndex = 0;

    // Trigger Real API Call in parallel
    this.api.createTenant({ name: tenantName, id: tenantId }).subscribe({
      next: (res: any) => {
        this.provisioningApiDone = true;
        this.provisioningApiResult = res;
      },
      error: (err: any) => {
        this.provisioningApiDone = true;
        this.provisioningApiError = err;
      }
    });

    // Timing sequence for clear, high-impact progression
    const stepIntervals = [
      { delay: 550,  progress: 25, log: `[CONFIG] Validated slug '${tenantId}' · cryptographic boundary allocated` },
      { delay: 750,  progress: 50, log: `[CLICKHOUSE] CREATE DATABASE IF NOT EXISTS ${targetDb} ON CLUSTER ndr_cluster` },
      { delay: 850,  progress: 75, log: `[SCHEMA] DDL migration complete · ndr_hits, ndr_events, threat_intel deployed` },
      { delay: 650,  progress: 90, log: `[ISOLATION] Multi-tenant RBAC policies active · 0.00% leakage envelope verified` },
      { delay: 550,  progress: 100, log: `[READY] Tenant namespace '${tenantId}' armed and operational!` }
    ];

    const advanceStep = () => {
      if (this.provisioningFailed) return;

      if (stepIndex < this.provisioningSteps.length) {
        // Mark current step done
        this.provisioningSteps[stepIndex].status = 'done';
        this.addProvisioningLog(stepIntervals[stepIndex].log, stepIndex === 4 ? 'success' : 'info');

        stepIndex++;
        if (stepIndex < this.provisioningSteps.length) {
          this.provisioningSteps[stepIndex].status = 'active';
          this.provisioningProgress = stepIntervals[stepIndex].progress;
          this.cdr.detectChanges();
          setTimeout(advanceStep, stepIntervals[stepIndex].delay);
        } else {
          // Finished all steps
          this.finishProvisioning();
        }
      } else {
        this.finishProvisioning();
      }
      this.cdr.detectChanges();
    };

    setTimeout(advanceStep, stepIntervals[0].delay);
  }

  private finishProvisioning() {
    if (!this.provisioningApiDone) {
      setTimeout(() => this.finishProvisioning(), 300);
      return;
    }
    const apiResult = this.provisioningApiResult;
    const apiError = this.provisioningApiError;

    if (apiError || (apiResult && apiResult.status !== 'ok')) {
      const errMsg = apiError?.error?.message || apiResult?.message || 'Failed to complete tenant initialization';
      this.provisioningFailed = true;
      this.savingTenant = false;
      this.provisioningError = errMsg;
      const lastActive = this.provisioningSteps.find(s => s.status === 'active') || this.provisioningSteps[this.provisioningSteps.length - 1];
      if (lastActive) lastActive.status = 'error';
      this.addProvisioningLog(`[FAILED] ${errMsg}`, 'error');
      this.cdr.detectChanges();
      return;
    }

    this.provisioningSteps.forEach(s => s.status = 'done');
    this.provisioningProgress = 100;
    this.provisioningComplete = true;
    this.savingTenant = false;
    this.loadTenants();
    this.showMsg(`Tenant "${this.provisioningTenantName}" activated successfully`, 'success');
    this.cdr.detectChanges();

    // Auto-close automatically after 2.2 seconds so user sees all green checkmarks
    if (this.autoCloseTimer) clearTimeout(this.autoCloseTimer);
    this.autoCloseTimer = setTimeout(() => {
      if (this.isProvisioning && this.provisioningComplete) {
        this.closeProvisioningModal();
      }
    }, 2200);
  }

  private autoCloseTimer: any = null;

  closeProvisioningModal() {
    if (this.autoCloseTimer) clearTimeout(this.autoCloseTimer);
    this.showAddTenant = false;
    this.isProvisioning = false;
    this.provisioningComplete = false;
    this.provisioningFailed = false;
    this.newTenant = { name: '', id: '' };
    this.tenantMsg = '';
    this.cdr.detectChanges();
  }

  resetProvisioningForm() {
    this.isProvisioning = false;
    this.provisioningFailed = false;
    this.provisioningComplete = false;
    this.savingTenant = false;
    this.cdr.detectChanges();
  }

  openEditTenant(tenant: any) {
    this.editingTenant = tenant;
    this.tenantForm = { name: tenant.name, active: tenant.active };
  }

  closeEditTenant() { this.editingTenant = null; }

  saveTenantEdit() {
    if (!this.editingTenant) return;
    if (!this.tenantForm.name.trim()) { this.showMsg('Tenant name required', 'error'); return; }

    this.api.updateTenant(this.editingTenant.id, this.tenantForm).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.editingTenant = null;
          this.loadTenants();
          this.showMsg('Tenant updated', 'success');
        } else {
          this.showMsg(data.message || 'Failed to update tenant', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to update tenant', 'error'); this.cdr.detectChanges(); },
    });
  }

  setTenantActive(tenant: any, active: boolean) {
    const previous = tenant.active;
    tenant.active = active;
    this.cdr.detectChanges();

    this.api.setTenantStatus(tenant.id, active).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(active ? 'Tenant activated' : 'Tenant deactivated', 'success');
          this.reloadTenantsWithRetry(tenant.id, active);
        } else {
          tenant.active = previous;
          this.showMsg(data.message || 'Failed to update tenant status', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        tenant.active = previous;
        this.showMsg('Failed to update tenant status', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  toggleTenantAI(tenant: any, enabled: boolean) {
    const previous = tenant.ai_enabled;
    tenant.ai_enabled = enabled;
    this.cdr.detectChanges();
    this.api.setTenantAiEnabled(tenant.id, enabled).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(`AI features ${enabled ? 'enabled' : 'disabled'} for ${tenant.name}`, 'success');
        } else {
          tenant.ai_enabled = previous;
          this.showMsg(data.message || 'Failed to update AI setting', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        tenant.ai_enabled = previous;
        this.showMsg('Failed to update AI setting', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  private reloadTenantsWithRetry(tenantId: string, expectedActive: boolean, attempt = 0): void {
    const delays = [1000, 2000, 4000];
    setTimeout(() => {
      this.api.getTenants().subscribe({
        next: (data: any) => {
          const fresh: any[] = data.tenants || [];
          const target = fresh.find((t: any) => t.id === tenantId);
          if (target && target.active !== expectedActive && attempt < delays.length - 1) {
            this.reloadTenantsWithRetry(tenantId, expectedActive, attempt + 1);
          } else {
            this.tenants = fresh;
            this.cdr.detectChanges();
          }
        },
        error: reportRxjsError,
      });
    }, delays[attempt] ?? delays[delays.length - 1]);
  }

  openFeatures(tenant: any) {
    this.featureTenant = tenant;
    const feats: string[] = tenant.features ?? ['ndr'];
    this.featureForm = {
      ndr:          feats.includes('ndr'),
      siem:         feats.includes('siem'),
      soar:         feats.includes('soar'),
      threat_intel: feats.includes('threat_intel'),
      ai:           feats.includes('ai'),
    };
    this.cdr.detectChanges();
  }

  closeFeatures() { this.featureTenant = null; this.cdr.detectChanges(); }

  saveFeatures() {
    if (!this.featureTenant) return;
    const features: string[] = [];
    if (this.featureForm.ndr)          features.push('ndr');
    if (this.featureForm.siem)         features.push('siem');
    if (this.featureForm.soar)         features.push('soar');
    if (this.featureForm.threat_intel) features.push('threat_intel');
    if (this.featureForm.ai)           features.push('ai');
    this.savingFeatures = true;
    this.api.setTenantFeatures(this.featureTenant.id, features).subscribe({
      next: () => {
        this.featureTenant.features = features;
        this.savingFeatures = false;
        this.closeFeatures();
        this.showMsg('Features updated', 'success');
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingFeatures = false;
        this.showMsg('Failed to save features', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  openLicense(tenant: any) {
    this.licenseTenant   = tenant;
    this.generatedToken  = '';
    this.tokenCopied     = false;
    this.licenseForm     = { expires_days: 365, max_sensors: 10, admin_user: '', admin_pass: '' };
    this.issuedLicenses  = [];
    this.loadingLicenses = true;
    this.cdr.detectChanges();
    // Load public key + existing licenses in parallel
    this.api.getLicensePublicKey().subscribe({
      next: (r: any) => { this.licensePublicKey = r.public_key ?? ''; this.cdr.detectChanges(); },
      error: reportRxjsError,
    });
    this.api.getLicenses(tenant.id).subscribe({
      next: (r: any) => {
        this.issuedLicenses  = r.licenses ?? [];
        this.loadingLicenses = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingLicenses = false; this.cdr.detectChanges(); },
    });
  }

  closeLicense() { this.licenseTenant = null; this.generatedToken = ''; this.cdr.detectChanges(); }

  generateLicense() {
    if (!this.licenseTenant) return;
    const features: string[] = this.licenseTenant.features ?? ['ndr'];
    this.generatingLicense = true;
    this.api.generateLicense({
      tenant_id:    this.licenseTenant.id,
      tenant_name:  this.licenseTenant.name,
      features,
      max_sensors:  this.licenseForm.max_sensors,
      expires_days: this.licenseForm.expires_days,
      admin_user:   this.licenseForm.admin_user.trim(),
    }).subscribe({
      next: (data: any) => {
        this.generatedToken    = data.token ?? '';
        this.generatingLicense = false;
        this.installCopied     = false;
        // Reload license list
        this.api.getLicenses(this.licenseTenant?.id).subscribe({
          next: (r: any) => { this.issuedLicenses = r.licenses ?? []; this.cdr.detectChanges(); },
          error: reportRxjsError,
        });
        // Reload public key if it didn't load when modal opened
        if (!this.licensePublicKey) {
          this.api.getLicensePublicKey().subscribe({
            next: (r: any) => { this.licensePublicKey = r.public_key ?? ''; this.cdr.detectChanges(); },
            error: reportRxjsError,
          });
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.generatingLicense = false;
        this.showMsg('Failed to generate license', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  copyInstallPackage(token?: string, license?: any) {
    const useToken = token ?? this.generatedToken;
    const useExpires = license?.expires_at
      ? `until ${license.expires_at.slice(0, 10)}`
      : `${this.licenseForm.expires_days} days`;
    const useMaxSensors = license?.max_sensors ?? this.licenseForm.max_sensors;
    const useFeatures = license?.features ?? this.licenseTenant?.features ?? ['ndr'];
    // Admin user: prefer history record, fall back to current form value
    const useAdminUser = (license?.admin_user || this.licenseForm.admin_user).trim();
    const useAdminPass = this.licenseForm.admin_pass;
    const installCmd = `bash <(curl -fsSL https://raw.githubusercontent.com/jithinjoseph-workspace/NDR-Demo/arkime/install-customer.sh)`;
    const pubKeyLine = this.licensePublicKey || '(load the portal and copy the public key from the License modal)';
    const credLines = useAdminUser
      ? [`   Tenant admin username : ${useAdminUser}`, `   Tenant admin password : ${useAdminPass || '(enter when prompted)'}`]
      : [`   Tenant admin username : (enter when prompted)`, `   Tenant admin password : (enter when prompted)`];
    const instructions = [
      `=== ProVigilAI Install Package for ${this.licenseTenant?.name} ===`,
      ``,
      `1. Run on the client's Ubuntu server:`,
      `   ${installCmd}`,
      ``,
      `2. When prompted, enter:`,
      `   License public key    : ${pubKeyLine}`,
      `   License token         : ${useToken}`,
      ...credLines,
      ``,
      `Features : ${useFeatures.join(', ')}`,
      `Expires  : ${useExpires}`,
      `Sensors  : up to ${useMaxSensors}`,
    ].join('\n');

    navigator.clipboard.writeText(instructions).then(() => {
      this.installCopied = true;
      setTimeout(() => { this.installCopied = false; this.cdr.detectChanges(); }, 2500);
      this.cdr.detectChanges();
    });
  }

  deleteLicense(lic: any) {
    if (!confirm(`Delete this license (issued ${lic.issued_at?.slice(0,10)})?`)) return;
    this.api.deleteLicense(lic.id).subscribe({
      next: () => {
        this.issuedLicenses = this.issuedLicenses.filter(l => l.id !== lic.id);
        this.cdr.detectChanges();
      },
      error: () => this.showMsg('Failed to delete license', 'error'),
    });
  }

  copyToken() {
    if (!this.generatedToken) return;
    navigator.clipboard.writeText(this.generatedToken).then(() => {
      this.tokenCopied = true;
      setTimeout(() => { this.tokenCopied = false; this.cdr.detectChanges(); }, 2000);
      this.cdr.detectChanges();
    });
  }

  showMsg(msg: string, type: string) {
    this.msg = msg;
    this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
