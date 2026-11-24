import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { LucideAngularModule, ShieldAlert, Plus, Trash2, RefreshCw } from 'lucide-angular';

interface Honeypot {
  id:          string;
  tenant_id:   string;
  name:        string;
  cidr:        string;
  description: string;
  active:      boolean;
  created_at:  string;
}

@Component({
  selector: 'app-honeypots',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './honeypots.html',
  styleUrl: './honeypots.scss',
})
export class Honeypots implements OnInit {
  ShieldAlertIcon = ShieldAlert;
  PlusIcon        = Plus;
  TrashIcon       = Trash2;
  RefreshIcon     = RefreshCw;

  honeypots: Honeypot[] = [];
  loading    = false;
  error      = '';
  success    = '';

  showForm   = false;
  formName   = '';
  formCidr   = '';
  formDesc   = '';
  submitting = false;

  constructor(
    private api:  Api,
    private auth: AuthService,
    private cdr:  ChangeDetectorRef,
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.error   = '';
    this.api.getHoneypots().subscribe({
      next: (r: any) => {
        this.honeypots = r.honeypots ?? [];
        this.loading   = false;
        this.cdr.markForCheck();
      },
      error: (e: any) => {
        this.error   = e?.error?.message ?? 'Failed to load honeypots';
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  toggleForm(): void { this.showForm = !this.showForm; }

  submit(): void {
    if (!this.formName.trim() || !this.formCidr.trim()) {
      this.error = 'Name and CIDR are required';
      return;
    }
    this.submitting = true;
    this.error      = '';
    this.api.addHoneypot(this.formName, this.formCidr, this.formDesc).subscribe({
      next: () => {
        this.submitting = false;
        this.showForm   = false;
        this.formName   = '';
        this.formCidr   = '';
        this.formDesc   = '';
        this.success    = 'Honeypot added';
        this.load();
        setTimeout(() => { this.success = ''; this.cdr.markForCheck(); }, 3000);
      },
      error: (e: any) => {
        this.error      = e?.error?.message ?? 'Failed to add honeypot';
        this.submitting = false;
        this.cdr.markForCheck();
      },
    });
  }

  remove(hp: Honeypot): void {
    if (!confirm(`Remove honeypot "${hp.name}"?`)) return;
    this.api.deleteHoneypot(hp.id).subscribe({
      next: () => {
        this.success = 'Honeypot removed';
        this.load();
        setTimeout(() => { this.success = ''; this.cdr.markForCheck(); }, 3000);
      },
      error: (e: any) => {
        this.error = e?.error?.message ?? 'Failed to remove honeypot';
        this.cdr.markForCheck();
      },
    });
  }

  canManage(): boolean {
    const role = this.auth.getUser()?.role ?? '';
    return ['super_admin', 'admin', 'tenant_admin'].includes(role);
  }
}
