import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  AlertTriangle, CircleCheck, LoaderCircle, Save,
  Mail, Server, ShieldCheck, Lock, Send, KeyRound, Clock, Activity, RefreshCw, Eye, EyeOff, Zap, ShieldAlert
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';

@Component({
  selector: 'app-smtp-config',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './smtp-config.html',
  styleUrl: './smtp-config.css',
})
export class SmtpConfig implements OnInit {
  Math = Math;

  CheckIcon       = CircleCheck;
  ErrorIcon       = AlertTriangle;
  LoadingIcon     = LoaderCircle;
  SaveIcon        = Save;
  MailIcon        = Mail;
  ServerIcon      = Server;
  ShieldIcon      = ShieldCheck;
  LockIcon        = Lock;
  SendIcon        = Send;
  KeyRoundIcon    = KeyRound;
  ClockIcon       = Clock;
  ActivityIcon    = Activity;
  RefreshIcon     = RefreshCw;
  EyeIcon         = Eye;
  EyeOffIcon      = EyeOff;
  ZapIcon         = Zap;
  ShieldAlertIcon = ShieldAlert;

  smtpConfig: any = { host: '', port: 587, user: '', password: '', alert_enabled: false, alert_to: [], alert_level: 12, max_per_hour: 12 };
  /** Recipients as typed (comma separated). */
  alertTo = '';
  hasPassword = false;
  levels = Array.from({ length: 16 }, (_, i) => i + 1);
  testTo = '';
  testing = false;
  savingSmtp   = false;
  smtpMessage  = '';
  smtpError    = '';
  showPassword = false;

  constructor(private api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {}

  get isConfigured(): boolean {
    return !!(this.smtpConfig.user && this.smtpConfig.host);
  }

  get tlsMode(): string {
    if (this.smtpConfig.port === 465) return 'Implicit SSL/TLS';
    if (this.smtpConfig.port === 587) return 'Explicit STARTTLS';
    return 'Opportunistic / Plain';
  }

  setPort(p: number) {
    this.smtpConfig.port = p;
  }

  ngOnInit() {
    this.loadSmtpConfig();
  }

  loadSmtpConfig() {
    this.api.getGlobalSmtp().subscribe({
      next: (data: any) => {
        if (data.status === 'ok' && data.config) {
          this.smtpConfig = data.config;
          this.alertTo = (data.config.alert_to || []).join(', ');
          this.hasPassword = !!data.has_password;
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => { console.error('Failed to load SMTP config', err); },
    });
  }

  saveSmtpConfig() {
    this.savingSmtp = true; this.smtpMessage = ''; this.smtpError = '';
    this.smtpConfig.alert_to = this.alertTo.split(',').map((x: string) => x.trim()).filter((x: string) => x);
    this.api.updateGlobalSmtp(this.smtpConfig).subscribe({
      next: () => {
        this.savingSmtp   = false;
        this.smtpMessage  = 'SMTP configuration saved';
        this.smtpConfig.password = '';
        this.loadSmtpConfig();
        this.cdr.detectChanges();
        setTimeout(() => { this.smtpMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: (err: any) => {
        this.savingSmtp  = false;
        this.smtpError   = err?.error?.message || 'Failed to save SMTP configuration';
        this.cdr.detectChanges();
      },
    });
  }

  sendTest() {
    this.testing = true; this.smtpMessage = ''; this.smtpError = '';
    this.api.testGlobalSmtp(this.testTo.trim()).subscribe({
      next: (r: any) => { this.testing = false; this.smtpMessage = r?.message || 'Test e-mail sent'; this.cdr.detectChanges(); },
      error: (err: any) => { this.testing = false; this.smtpError = err?.error?.message || 'Test e-mail failed'; this.cdr.detectChanges(); },
    });
  }
}
