import { Component, OnInit, ChangeDetectorRef, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
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

    constructor(private api: Api, private cdr: ChangeDetectorRef) {}

    ngOnInit() {
        this.loadSettings();
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
