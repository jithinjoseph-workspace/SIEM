import { Component, OnInit, ChangeDetectorRef, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { SiemService } from '../../../services/siem/siem.service';
import { AgentDeployService } from '../../../services/siem/agent-deploy';
import {
    LucideAngularModule,
    TriangleAlert,
    Bell,
    CircleCheck,
    Database,
    LoaderCircle,
    Save,
    ShieldAlert,
    SlidersHorizontal,
    Workflow,
} from 'lucide-angular';

@Component({
    selector: 'app-tenant-settings',
    standalone: true,
    encapsulation: ViewEncapsulation.None,
    imports: [CommonModule, FormsModule, LucideAngularModule],
    templateUrl: './settings.html',
    styleUrl: './settings.css'
})
export class TenantSettings implements OnInit {
    loading = true;
    saving  = false;
    message = '';
    error   = '';

    thresholds = {
        store_threshold:    10,
        alert_threshold:    75,
        critical_threshold: 90,
        soar_threshold:     75,
    };

    sensitiveCountries = 'AM,AZ,BY,CN,CU,DZ,GE,HK,IL,IN,IQ,IR,KG,KP,KZ,LY,MD,MO,PK,RU,SD,SS,SY,TJ,TM,TW,UA,UZ';

    SlidersIcon  = SlidersHorizontal;
    SaveIcon     = Save;
    CheckIcon    = CircleCheck;
    ErrorIcon    = TriangleAlert;
    DatabaseIcon = Database;
    BellIcon     = Bell;
    CriticalIcon = ShieldAlert;
    WorkflowIcon = Workflow;
    LoadingIcon  = LoaderCircle;

    /** The key new agents of this tenant enroll with (X-Tenant-Key). */
    agentKey = '';
    agentKeyShown = false;
    agentKeyMessage = '';

    /** This tenant's alert e-mails (sent through the platform SMTP account). */
    alertMail = { enabled: false, recipients: '', min_level: 12, groups: '', max_per_hour: 12 };
    alertMailMessage = '';
    alertMailError = '';
    smtpReady = true;

    /** The scheduled PDF report e-mail, and the on-demand download. */
    report = { enabled: false, frequency: 'weekly', hour_utc: 6, recipients: '' };
    reportHours = 168;
    /** Optional report filters, a breakdown (two fields) and the sample alerts. */
    reportFilter = { title: '', group: '', rule: '', level: '', agent: '', srcip: '', user: '', location: '', file: '', by: '', samples: false };
    reportMessage = '';
    reportError = '';
    reportBusy = false;

    constructor(private api: Api, private cdr: ChangeDetectorRef, private siem: SiemService, private deploy: AgentDeployService) {}

    ngOnInit() {
        this.loadSettings();
        this.siem.getAlertMail().subscribe({
            next: (r: any) => {
                const s = r?.settings || {};
                this.alertMail = { enabled: !!s.enabled, recipients: (s.recipients || []).join(', '), min_level: s.min_level ?? 12, groups: (s.groups || []).join(', '), max_per_hour: s.max_per_hour ?? 12 };
                this.smtpReady = r?.smtp_ready !== false;
                this.cdr.detectChanges();
            },
            error: () => {},
        });
        this.siem.getReportSchedule().subscribe({
            next: (r: any) => {
                const s = r?.schedule || {};
                this.report = { enabled: !!s.enabled, frequency: s.frequency || 'weekly', hour_utc: s.hour_utc ?? 6, recipients: (s.recipients || []).join(', ') };
                this.cdr.detectChanges();
            },
            error: () => {},
        });
        this.deploy.tenantKey().subscribe({
            next: (r: any) => { this.agentKey = r?.key || ''; this.cdr.detectChanges(); },
            error: () => {},
        });
    }

    rotateAgentKey() {
        if (!confirm('Create a new agent key for this tenant?\n\nAgents already enrolled keep working. Install commands and scripts made with the old key stop enrolling new agents.')) return;
        this.siem.rotateTenantAgentKey().subscribe({
            next: (r: any) => {
                this.agentKey = r?.agent_key || this.agentKey;
                this.agentKeyShown = true;
                this.agentKeyMessage = 'New key created. Use it in new install commands.';
                this.cdr.detectChanges();
            },
            error: (e: any) => { this.agentKeyMessage = e?.status === 403 ? 'Only the tenant admin can rotate the key.' : 'Could not rotate the key.'; this.cdr.detectChanges(); },
        });
    }

    private list(s: string): string[] {
        return s.split(/[,;\s]+/).map(x => x.trim()).filter(Boolean);
    }

    private apiError(e: any): string {
        return e?.status === 403 ? 'Only the tenant admin can change this.' : (e?.error?.message || 'Request failed');
    }

    private flash(set: (m: string) => void, m: string) {
        set(m);
        this.cdr.detectChanges();
        setTimeout(() => { set(''); this.cdr.detectChanges(); }, 4000);
    }

    saveAlertMail(then?: () => void) {
        this.alertMailError = '';
        const a = this.alertMail;
        this.siem.saveAlertMail({ enabled: a.enabled, recipients: this.list(a.recipients), min_level: +a.min_level, groups: this.list(a.groups), max_per_hour: +a.max_per_hour }).subscribe({
            next: () => { this.flash(m => this.alertMailMessage = m, 'Alert e-mail settings saved'); then?.(); },
            error: (e: any) => { this.alertMailError = this.apiError(e); this.cdr.detectChanges(); },
        });
    }

    testAlertMail() {
        this.saveAlertMail(() => this.siem.testAlertMail().subscribe({
            next: (r: any) => this.flash(m => this.alertMailMessage = m, r?.message || 'Test e-mail sent'),
            error: (e: any) => { this.alertMailError = this.apiError(e); this.cdr.detectChanges(); },
        }));
    }

    saveReport(then?: () => void) {
        this.reportError = '';
        const r = this.report;
        this.siem.saveReportSchedule({ enabled: r.enabled, frequency: r.frequency, hour_utc: +r.hour_utc, recipients: this.list(r.recipients) }).subscribe({
            next: () => { this.flash(m => this.reportMessage = m, 'Report schedule saved'); then?.(); },
            error: (e: any) => { this.reportError = this.apiError(e); this.cdr.detectChanges(); },
        });
    }

    sendReportNow() {
        this.saveReport(() => {
            this.reportBusy = true;
            this.siem.sendReportNow().subscribe({
                next: (r: any) => { this.reportBusy = false; this.flash(m => this.reportMessage = m, r?.message || 'Report sent'); },
                error: (e: any) => { this.reportBusy = false; this.reportError = this.apiError(e); this.cdr.detectChanges(); },
            });
        });
    }

    downloadReport() {
        this.reportBusy = true;
        this.reportError = '';
        this.siem.downloadReportPdf(+this.reportHours, this.reportFilter).subscribe({
            next: () => { this.reportBusy = false; this.cdr.detectChanges(); },
            error: (e: any) => { this.reportBusy = false; this.reportError = e?.status === 400 ? 'Check the filters: a rule is a number, a level 0 to 16' : 'The report could not be made'; this.cdr.detectChanges(); },
        });
    }

    loadSettings() {
        this.api.getSettings().subscribe({
            next: (data: any) => {
                const s = data.settings || {};
                this.thresholds = {
                    store_threshold:    s.store_threshold    ?? 10,
                    alert_threshold:    s.alert_threshold    ?? 75,
                    critical_threshold: s.critical_threshold ?? 90,
                    soar_threshold:     s.soar_threshold     ?? 75,
                };
                if (s.sensitive_countries) {
                    this.sensitiveCountries = s.sensitive_countries;
                }
                this.loading = false;
                this.cdr.detectChanges();
            },
            error: () => {
                this.loading = false;
                this.cdr.detectChanges();
            }
        });
    }

    saveSettings() {
        this.saving = true;
        this.message = '';
        this.error = '';
        this.api.updateSettings({
            ...this.thresholds,
            sensitive_countries: this.sensitiveCountries.trim()
        }).subscribe({
            next: () => {
                this.saving = false;
                this.message = 'Settings saved';
                this.cdr.detectChanges();
                setTimeout(() => { this.message = ''; this.cdr.detectChanges(); }, 3000);
            },
            error: () => {
                this.saving = false;
                this.error = 'Failed to save settings';
                this.cdr.detectChanges();
            }
        });
    }



}
