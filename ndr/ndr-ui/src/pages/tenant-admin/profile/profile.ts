import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, signal, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  LucideAngularModule,
  User, Mail, ShieldCheck, Eye, EyeOff, Copy, AlertCircle, Pencil, Loader,
  Settings, HelpCircle, ChevronRight,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

@Component({
  selector: 'app-profile',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './profile.html',
  styleUrl: './profile.css',
})
export class Profile implements OnInit {
  UserIcon        = User;
  MailIcon        = Mail;
  ShieldIcon      = ShieldCheck;
  EyeIcon         = Eye;
  EyeOffIcon      = EyeOff;
  CopyIcon        = Copy;
  AlertCircleIcon = AlertCircle;
  Edit2Icon       = Pencil;
  LoaderIcon      = Loader;
  SettingsIcon    = Settings;
  SupportIcon     = HelpCircle;
  ChevronRightIcon = ChevronRight;

  readonly currentUser       = signal<any>({});
  readonly message           = signal('');
  readonly messageType       = signal<'success' | 'error'>('success');
  readonly loading           = signal(true);

  showSecretCode       = false;
  isEditingEmail       = false;
  editingEmailValue    = '';
  emailUpdateLoading   = false;
  generatingCode       = false;
  newlyGeneratedCode   = '';

  constructor(private api: Api, private auth: AuthService, private cdr: ChangeDetectorRef, private router: Router) {}

  goToSettings() { this.router.navigate(['/tenant-admin/settings']); }
  goToSupport()  { this.router.navigate(['/tenant-admin/support']);  }

  ngOnInit() {
    // Always fetch fresh per-user data from backend — never rely on stale localStorage
    this.auth.refreshUser().subscribe({
      next: () => {
        this.currentUser.set(this.auth.getUser() || {});
        this.loading.set(false);
        this.cdr.markForCheck();
      },
      error: () => {
        // Fallback to localStorage on network error
        this.currentUser.set(this.auth.getUser() || {});
        this.loading.set(false);
        this.cdr.markForCheck();
      }
    });
  }

  copySecretCode() {
    const code = this.newlyGeneratedCode || this.currentUser()?.secret_code;
    if (code) navigator.clipboard.writeText(code);
  }

  generateSecretCode() {
    if (this.generatingCode) return;
    this.generatingCode = true;
    this.api.regenerateSecretCode().subscribe({
      next: (res: any) => {
        this.generatingCode = false;
        if (res.status === 'ok') {
          this.newlyGeneratedCode = res.secret_code;
          this.showSecretCode = true;
          this.showMessage('New secret code generated — save it somewhere safe!', 'success');
          this.auth.refreshUser().subscribe({
            next: () => { this.currentUser.set(this.auth.getUser() || {}); this.cdr.markForCheck(); },
            error: () => {},
          });
        } else {
          this.showMessage(res.message || 'Failed to generate code', 'error');
        }
      },
      error: () => {
        this.generatingCode = false;
        this.showMessage('Failed to generate code', 'error');
      }
    });
  }

  startEmailEdit() {
    this.isEditingEmail    = true;
    this.editingEmailValue = this.currentUser()?.gmail || '';
  }

  cancelEmailEdit() {
    this.isEditingEmail    = false;
    this.editingEmailValue = '';
  }

  saveRecoveryEmail() {
    const val = this.editingEmailValue.trim();
    if (!val) { this.showMessage('Email address cannot be empty', 'error'); return; }
    if (!val.includes('@')) { this.showMessage('Invalid email address format', 'error'); return; }
    this.emailUpdateLoading = true;
    this.api.updateProfileGmail(val).subscribe({
      next: (res: any) => {
        this.emailUpdateLoading = false;
        if (res.status === 'ok') {
          this.showMessage('Recovery email updated successfully', 'success');
          this.isEditingEmail = false;
          // Sync localStorage so the new value persists across navigation
          this.auth.refreshUser().subscribe({
            next: () => {
              this.currentUser.set(this.auth.getUser() || {});
              this.cdr.markForCheck();
            },
            error: () => {},
          });
        } else {
          this.showMessage(res.message || 'Failed to update email', 'error');
        }
      },
      error: (err: any) => {
        this.emailUpdateLoading = false;
        this.showMessage(err.error?.message || 'Failed to update email', 'error');
      }
    });
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
  }
}
