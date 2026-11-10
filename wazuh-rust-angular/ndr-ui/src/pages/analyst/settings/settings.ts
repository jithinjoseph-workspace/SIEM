import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import {
    LucideAngularModule,
    AlertTriangle,
    Bell,
    Bot,
    CheckCircle2,
    Database,
    Eye,
    EyeOff,
    KeyRound,
    LoaderCircle,
    Plus,
    Save,
    ShieldAlert,
    SlidersHorizontal,
    Trash2,
    Workflow,
    Zap
} from 'lucide-angular';

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, LucideAngularModule],
    templateUrl: './settings.html',
    styleUrl: './settings.css'
})
export class Settings implements OnInit {
    loading    = true;
    saving     = false;
    message    = '';
    error      = '';

    isSuperAdmin = false;

    thresholds = {
        store_threshold:    10,
        alert_threshold:    75,
        critical_threshold: 90,
        soar_threshold:     75
    };

    sensitiveCountries = 'AM,AZ,BY,CN,CU,DZ,GE,HK,IL,IN,IQ,IR,KG,KP,KZ,LY,MD,MO,PK,RU,SD,SS,SY,TJ,TM,TW,UA,UZ';

    // Legacy single-provider config (kept for backwards compat)
    aiConfig = {
        ai_provider:      'custom',
        ai_api_key:       '',
        ai_model:         '',
        ai_base_url:      '',
        ai_endpoint_path: '',
        ai_msg_format:    'openai',
        ai_key_set:       false
    };



    SlidersIcon  = SlidersHorizontal;
    SaveIcon     = Save;
    CheckIcon    = CheckCircle2;
    ErrorIcon    = AlertTriangle;
    DatabaseIcon = Database;
    BellIcon     = Bell;
    CriticalIcon = ShieldAlert;
    WorkflowIcon = Workflow;
    LoadingIcon  = LoaderCircle;
    BotIcon      = Bot;
    KeyIcon      = KeyRound;
    EyeIcon      = Eye;
    EyeOffIcon   = EyeOff;
    PlusIcon     = Plus;
    TrashIcon    = Trash2;
    TestIcon     = Zap;

    constructor(
        private api: Api,
        private auth: AuthService,
        private cdr: ChangeDetectorRef
    ) {}

    ngOnInit() {
        const user = this.auth.getUser();
        this.isSuperAdmin = user?.role === 'super_admin';
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
