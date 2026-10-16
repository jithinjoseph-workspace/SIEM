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

    constructor(private api: Api, private cdr: ChangeDetectorRef, private siem: SiemService, private deploy: AgentDeployService) {}

    ngOnInit() {
        this.loadSettings();
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
