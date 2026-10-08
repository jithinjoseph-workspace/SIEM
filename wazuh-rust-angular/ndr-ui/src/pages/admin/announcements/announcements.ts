import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Plus, RefreshCw, Search, Trash2, X,
} from 'lucide-angular';
import { Announcement, Api } from '../../../services/api/api';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
type AnnouncementType     = 'info' | 'maintenance' | 'update' | 'critical';
type AnnouncementAudience = 'all' | 'tenant_admins' | 'tenant';

interface AnnouncementDraft {
  title: string; message: string; type: AnnouncementType;
  audience: AnnouncementAudience; tenant_id: string;
  starts_at: string; ends_at: string; active: boolean;
}

@Component({
  selector: 'app-announcements',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './announcements.html',
  styleUrl: './announcements.css',
})
export class Announcements implements OnInit {
  PlusIcon    = Plus;
  RefreshIcon = RefreshCw;
  SearchIcon  = Search;
  TrashIcon   = Trash2;
  XIcon       = X;

  tenants: any[]              = [];
  announcements: Announcement[] = [];
  loadingAnnouncements        = false;
  savingAnnouncement          = false;
  announcementSearch          = '';
  announcementAudience        = 'all_audiences';
  showAddAnnouncement         = false;
  pendingDeleteAnnouncement: Announcement | null = null;

  announcementStartDate = '';
  announcementStartTime = '';
  announcementEndDate   = '';
  announcementEndTime   = '';

  readonly timeSlots = (() => {
    const slots: { value: string; label: string }[] = [];
    for (let h = 0; h < 24; h++) {
      for (const m of [0, 30]) {
        const hh = String(h).padStart(2, '0');
        const mm = String(m).padStart(2, '0');
        const suffix   = h < 12 ? 'AM' : 'PM';
        const displayH = h === 0 ? 12 : h > 12 ? h - 12 : h;
        slots.push({ value: `${hh}:${mm}`, label: `${displayH}:${mm} ${suffix}` });
      }
    }
    return slots;
  })();

  get todayDate(): string { return new Date().toISOString().split('T')[0]; }

  get filteredStartTimeSlots(): { value: string; label: string }[] {
    if (this.announcementStartDate !== this.todayDate) return this.timeSlots;
    const now = new Date();
    const currentMinutes = now.getHours() * 60 + now.getMinutes();
    return this.timeSlots.filter(t => {
      const [h, m] = t.value.split(':').map(Number);
      return (h * 60 + m) > currentMinutes;
    });
  }

  get filteredEndTimeSlots(): { value: string; label: string }[] {
    if (this.announcementEndDate && this.announcementStartDate &&
        this.announcementEndDate === this.announcementStartDate && this.announcementStartTime) {
      const [sh, sm] = this.announcementStartTime.split(':').map(Number);
      const startMinutes = sh * 60 + sm;
      return this.timeSlots.filter(t => {
        const [h, m] = t.value.split(':').map(Number);
        return (h * 60 + m) > startMinutes;
      });
    }
    return this.timeSlots;
  }

  newAnnouncement: AnnouncementDraft = {
    title: '', message: '', type: 'info', audience: 'tenant_admins',
    tenant_id: '', starts_at: '', ends_at: '', active: true,
  };

  msg     = '';
  msgType = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadAnnouncements();
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants = data.tenants || []; this.cdr.detectChanges(); },
      error: reportRxjsError,
    });
  }

  loadAnnouncements() {
    this.loadingAnnouncements = true;
    this.api.getAnnouncements().subscribe({
      next: announcements => {
        this.announcements = announcements.map(a => this.normalizeAnnouncement(a));
        this.loadingAnnouncements = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingAnnouncements = false; this.showMsg('Failed to load announcements', 'error'); this.cdr.detectChanges(); },
    });
  }

  get activeAnnouncements()   { return this.announcements.filter(a => a.active).length; }
  get filteredAnnouncements() {
    const query = this.announcementSearch.trim().toLowerCase();
    return this.announcements.filter(a => {
      const tenantId = this.announcementTenantId(a);
      const matchesAudience =
        this.announcementAudience === 'all_audiences' ||
        a.audience === this.announcementAudience ||
        tenantId === this.announcementAudience;
      const matchesQuery = !query || a.title.toLowerCase().includes(query) || a.message.toLowerCase().includes(query) ||
        this.announcementTypeLabel(a.type).toLowerCase().includes(query) || this.announcementAudienceLabel(a).toLowerCase().includes(query);
      return matchesAudience && matchesQuery;
    });
  }

  get canCreateAnnouncement() {
    const endAfterStart = !this.newAnnouncement.ends_at || !this.newAnnouncement.starts_at ||
      this.newAnnouncement.ends_at > this.newAnnouncement.starts_at;
    return !!this.newAnnouncement.title.trim() && !!this.newAnnouncement.message.trim() &&
      (this.newAnnouncement.audience !== 'tenant' || !!this.newAnnouncement.tenant_id) && endAfterStart;
  }

  get endBeforeStartError(): boolean {
    return !!this.newAnnouncement.ends_at && !!this.newAnnouncement.starts_at &&
      this.newAnnouncement.ends_at <= this.newAnnouncement.starts_at;
  }

  addAnnouncement() {
    if (!this.canCreateAnnouncement) { this.showMsg('Title, message, and audience are required', 'error'); return; }
    this.savingAnnouncement = true;
    this.api.createAnnouncement(this.buildAnnouncementPayload(this.newAnnouncement)).subscribe({
      next: (data: any) => {
        this.savingAnnouncement = false;
        if (data.status === 'ok') {
          this.showAddAnnouncement = false;
          this.resetAnnouncementForm();
          this.loadAnnouncements();
          this.showMsg('Announcement created', 'success');
        } else {
          this.showMsg(data.message || 'Failed to create announcement', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => { this.savingAnnouncement = false; this.showMsg('Failed to create announcement', 'error'); this.cdr.detectChanges(); },
    });
  }

  toggleAnnouncement(announcement: Announcement) {
    const previous = announcement.active;
    const nextActive = !announcement.active;
    announcement.active = nextActive;
    this.cdr.detectChanges();

    this.api.updateAnnouncement(announcement.id, {
      ...this.buildAnnouncementPayload({
        title: announcement.title, message: announcement.message, type: announcement.type,
        audience: announcement.audience, tenant_id: this.announcementTenantId(announcement),
        starts_at: announcement.starts_at || announcement.start_at || '',
        ends_at: announcement.ends_at || announcement.end_at || '', active: nextActive,
      }),
    }).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') { this.loadAnnouncements(); this.showMsg(nextActive ? 'Announcement activated' : 'Announcement deactivated', 'success'); }
        else { announcement.active = previous; this.showMsg(data.message || 'Failed to update announcement', 'error'); this.cdr.detectChanges(); }
      },
      error: () => { announcement.active = previous; this.showMsg('Failed to update announcement', 'error'); this.cdr.detectChanges(); },
    });
  }

  requestDeleteAnnouncement(announcement: Announcement) { this.pendingDeleteAnnouncement = announcement; }
  cancelDeleteAnnouncement()  { this.pendingDeleteAnnouncement = null; }

  confirmDeleteAnnouncement() {
    if (!this.pendingDeleteAnnouncement) return;
    const id = this.pendingDeleteAnnouncement.id;
    this.api.deleteAnnouncement(id).subscribe({
      next: (data: any) => {
        this.pendingDeleteAnnouncement = null;
        if (data.status === 'ok') { this.loadAnnouncements(); this.showMsg('Announcement deleted', 'success'); }
        else { this.showMsg(data.message || 'Failed to delete announcement', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to delete announcement', 'error'); this.cdr.detectChanges(); },
    });
  }

  closeAddAnnouncement()         { this.showAddAnnouncement = false; this.resetAnnouncementForm(); }
  onAnnouncementAudienceChange() { if (this.newAnnouncement.audience !== 'tenant') this.newAnnouncement.tenant_id = ''; }

  onStartDateTimeChange() { this.newAnnouncement.starts_at = this.buildIso(this.announcementStartDate, this.announcementStartTime); }
  onEndDateTimeChange()   { this.newAnnouncement.ends_at   = this.buildIso(this.announcementEndDate,   this.announcementEndTime); }

  clearStartDateTime() { this.announcementStartDate = ''; this.announcementStartTime = ''; this.newAnnouncement.starts_at = ''; }
  clearEndDateTime()   { this.announcementEndDate   = ''; this.announcementEndTime   = ''; this.newAnnouncement.ends_at   = ''; }

  private buildIso(date: string, time: string): string {
    if (!date) return '';
    return time ? `${date}T${time}:00` : `${date}T00:00:00`;
  }

  announcementTypeLabel(type: AnnouncementType) {
    switch (type) {
      case 'maintenance': return 'Maintenance';
      case 'update':      return 'Platform Update';
      case 'critical':    return 'Critical';
      default:            return 'Information';
    }
  }

  announcementAudienceLabel(announcement: Partial<AnnouncementDraft & Announcement>) {
    if (announcement.audience === 'tenant') return `Tenant: ${this.tenantName(this.announcementTenantId(announcement))}`;
    if (announcement.audience === 'tenant_admins') return 'Tenant admins';
    return 'All users';
  }

  announcementTypeClass(type: AnnouncementType) { return `announcement-${type}`; }

  tenantName(id: string) { return this.tenants.find(t => t.id === id)?.name || id; }

  private announcementTenantId(announcement: Partial<AnnouncementDraft & Announcement>) {
    if (announcement.tenant_id) return announcement.tenant_id;
    const targetTenants = announcement.target_tenants || [];
    return targetTenants.find((t: any) => t !== 'all') || '';
  }

  private buildAnnouncementPayload(announcement: AnnouncementDraft): Partial<Announcement> {
    return {
      title: announcement.title.trim(), message: announcement.message.trim(),
      type: announcement.type, audience: announcement.audience,
      tenant_id: announcement.audience === 'tenant' ? announcement.tenant_id : '',
      starts_at: announcement.starts_at || '', ends_at: announcement.ends_at || '',
      active: announcement.active,
    };
  }

  private normalizeAnnouncement(announcement: Announcement): Announcement {
    const targetTenant = this.announcementTenantId(announcement);
    return {
      ...announcement,
      type:     announcement.type     || 'info',
      audience: announcement.audience || (targetTenant ? 'tenant' : 'all'),
      tenant_id: targetTenant,
      starts_at: announcement.starts_at || announcement.start_at || '',
      ends_at:   announcement.ends_at   || announcement.end_at   || '',
      active:    announcement.active ?? announcement.status === 'active',
    };
  }

  private resetAnnouncementForm() {
    this.newAnnouncement = {
      title: '', message: '', type: 'info', audience: 'tenant_admins',
      tenant_id: '', starts_at: '', ends_at: '', active: true,
    };
    this.announcementStartDate = ''; this.announcementStartTime = '';
    this.announcementEndDate   = ''; this.announcementEndTime   = '';
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
