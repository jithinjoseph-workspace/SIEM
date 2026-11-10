import { ChangeDetectorRef, Directive, OnDestroy, OnInit } from '@angular/core';
import {
  CheckCircle,
  Forward,
  Inbox,
  MessageCircle,
  RefreshCcw,
  Reply,
  Send,
  ShieldCheck,
  Trash2,
} from 'lucide-angular';
import { Subscription, timer } from 'rxjs';
import { timeout } from 'rxjs/operators';
import { Api, SupportMessage } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

export interface SupportMessageView extends SupportMessage {
  statusLabelText: string;
  formattedCreatedAt: string;
  formattedRepliedAt: string;
  formattedUpdatedAt: string;
}

@Directive()
export abstract class SupportBase implements OnInit, OnDestroy {
  messages: SupportMessageView[] = [];
  loading = false;
  error = '';
  actionMessage = '';
  subject = '';
  category = 'General';
  message = '';
  activeReplyId = '';
  replyDrafts: Record<string, string> = {};
  busyAction: { id: string; action: string } | null = null;
  private refreshSub?: Subscription;
  private locallyTrackedUntil: Record<string, number> = {};

  categories = ['General', 'Access', 'Alert Review', 'Sensor', 'Incident', 'Other'];

  SendIcon = Send;
  RefreshIcon = RefreshCcw;
  ReplyIcon = Reply;
  TrashIcon = Trash2;
  ForwardIcon = Forward;
  CheckIcon = CheckCircle;
  InboxIcon = Inbox;
  MessageIcon = MessageCircle;
  ShieldIcon = ShieldCheck;

  constructor(
    protected api: Api,
    protected auth: AuthService,
    protected cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.loadSupportMessages();
    this.refreshSub = timer(10000, 10000).subscribe(() => this.loadSupportMessages(true));
  }

  ngOnDestroy(): void {
    this.refreshSub?.unsubscribe();
  }

  get user(): any {
    return this.auth.getUser();
  }

  get isTenantAdmin(): boolean {
    return this.user?.role === 'tenant_admin';
  }

  get isSuperAdmin(): boolean {
    return this.user?.role === 'super_admin' || this.user?.role === 'admin';
  }

  get isManager(): boolean {
    return this.isTenantAdmin || this.isSuperAdmin;
  }

  get canSubmitRequest(): boolean {
    return !this.isManager;
  }

  get pageTitle(): string {
    if (this.isSuperAdmin) return 'Forwarded Support';
    if (this.isTenantAdmin) return 'Tenant Support';
    return 'Support';
  }

  get pageDescription(): string {
    if (this.isSuperAdmin) {
      return 'Review escalated tenant requests and default-user support messages.';
    }
    if (this.isTenantAdmin) {
      return 'Review tenant user requests, reply, delete, or forward important items.';
    }
    return 'Send support requests to your tenant admin and track replies here.';
  }

  get openCount(): number {
    return this.messages.filter(item => item.status === 'open').length;
  }

  get forwardedCount(): number {
    return this.messages.filter(item => item.forwarded).length;
  }

  loadSupportMessages(silent = false): void {
    if (!silent) {
      this.loading = true;
    }
    this.error = '';

    this.api.getSupportMessages().pipe(timeout(12000)).subscribe({
      next: messages => {
        this.messages = this.mergePendingMessages(messages);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: error => {
        this.error = error?.error?.message || error?.message || 'Unable to load support messages.';
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  submitSupportRequest(): void {
    const subject = this.subject.trim();
    const message = this.message.trim();
    if (!subject || !message) {
      this.error = 'Subject and message are required.';
      return;
    }

    const optimisticId = `pending-${Date.now()}`;
    const optimisticMessage = this.enrichMessage(this.buildLocalMessage(optimisticId, subject, this.category, message, 'sending'));
    this.messages = [optimisticMessage, ...this.messages];
    this.locallyTrackedUntil[optimisticId] = Date.now() + 60000;
    this.busyAction = { id: 'new', action: 'send' };
    this.error = '';
    this.actionMessage = '';
    this.cdr.detectChanges();

    this.api.createSupportMessage({
      subject,
      category: this.category,
      message,
    }).pipe(timeout(12000)).subscribe({
      next: response => {
        this.busyAction = null;
        if (response?.status === 'ok') {
          this.subject = '';
          this.category = 'General';
          this.message = '';
          this.actionMessage = response.message || 'Support request sent.';
          const savedId = response.id || optimisticId;
          delete this.locallyTrackedUntil[optimisticId];
          this.locallyTrackedUntil[savedId] = Date.now() + 60000;
          this.replaceLocalMessage(optimisticId, this.enrichMessage({
            ...optimisticMessage,
            id: savedId,
            status: 'open',
            updated_at: new Date().toISOString(),
          }));
          this.cdr.detectChanges();
          this.loadSupportMessages(true);
        } else {
          this.removeLocalMessage(optimisticId);
          this.error = response?.message || 'Failed to send support request.';
          this.cdr.detectChanges();
        }
      },
      error: error => {
        this.busyAction = null;
        this.replaceLocalMessage(optimisticId, this.enrichMessage({
          ...optimisticMessage,
          status: 'syncing',
          updated_at: new Date().toISOString(),
        }));
        this.error = error?.error?.message || error?.message || 'Support request is still syncing. Use Refresh to confirm.';
        this.cdr.detectChanges();
      },
    });
  }

  reviewMessage(item: SupportMessage): void {
    this.runMessageAction(item, 'review', () => this.api.reviewSupportMessage(item.id));
  }

  forwardMessage(item: SupportMessage): void {
    this.runMessageAction(item, 'forward', () => this.api.forwardSupportMessage(item.id));
  }

  deleteMessage(item: SupportMessage): void {
    this.runMessageAction(item, 'delete', () => this.api.deleteSupportMessage(item.id));
  }

  toggleReply(item: SupportMessage): void {
    this.activeReplyId = this.activeReplyId === item.id ? '' : item.id;
    this.replyDrafts[item.id] = this.replyDrafts[item.id] || item.admin_reply || '';
    this.cdr.detectChanges();
  }

  sendReply(item: SupportMessage): void {
    const reply = (this.replyDrafts[item.id] || '').trim();
    if (!reply) {
      this.error = 'Reply message is required.';
      return;
    }

    this.runMessageAction(item, 'reply', () => this.api.replySupportMessage(item.id, reply), () => {
      this.activeReplyId = '';
    });
  }

  isBusy(item: SupportMessage, action?: string): boolean {
    return !!this.busyAction
      && this.busyAction.id === item.id
      && (!action || this.busyAction.action === action);
  }

  statusLabel(item: SupportMessage): string {
    if (item.forwarded && item.status === 'forwarded') return 'Forwarded';
    switch (item.status) {
      case 'sending':
        return 'Sending';
      case 'syncing':
        return 'Syncing';
      case 'reviewed':
        return 'Reviewed';
      case 'replied':
        return 'Replied';
      case 'deleted':
        return 'Deleted';
      default:
        return 'Open';
    }
  }

  formatDate(value: string): string {
    if (!value) return 'Not yet';
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const parsed = new Date(/Z$|[+-]\d{2}:\d{2}$/.test(normalized) ? normalized : `${normalized}Z`);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleString();
  }

  trackMessage(_index: number, item: SupportMessage): string {
    return item.id;
  }

  private runMessageAction(
    item: SupportMessage,
    action: string,
    request: () => any,
    afterSuccess?: () => void
  ): void {
    this.busyAction = { id: item.id, action };
    this.error = '';
    this.actionMessage = '';
    this.cdr.detectChanges();

    request().pipe(timeout(12000)).subscribe({
      next: (response: any) => {
        this.busyAction = null;
        if (response?.status === 'ok') {
          this.applyActionLocally(item, action);
          this.actionMessage = response.message || 'Support request updated.';
          afterSuccess?.();
          this.cdr.detectChanges();
          this.loadSupportMessages(true);
        } else {
          this.error = response?.message || 'Support action failed.';
          this.cdr.detectChanges();
        }
      },
      error: (error: any) => {
        this.busyAction = null;
        this.error = error?.error?.message || error?.message || 'Support action failed.';
        this.cdr.detectChanges();
      },
    });
  }

  private buildLocalMessage(
    id: string,
    subject: string,
    category: string,
    message: string,
    status: string
  ): SupportMessage {
    const now = new Date().toISOString();
    const user = this.user || {};
    return {
      id,
      tenant_id: user.tenant_id || '',
      sender_username: user.username || user.sub || 'me',
      sender_role: user.role || '',
      subject,
      category,
      message,
      status,
      admin_reply: '',
      replied_by: '',
      forwarded: 0,
      forwarded_by: '',
      deleted: 0,
      created_at: now,
      updated_at: now,
      replied_at: '',
      forwarded_at: '',
    };
  }

  private replaceLocalMessage(id: string, next: SupportMessageView): void {
    this.messages = this.messages.map(item => item.id === id ? next : item);
  }

  private removeLocalMessage(id: string): void {
    delete this.locallyTrackedUntil[id];
    this.messages = this.messages.filter(item => item.id !== id);
  }

  private mergePendingMessages(messages: SupportMessage[]): SupportMessageView[] {
    const now = Date.now();
    const backendIds = new Set(messages.map(item => item.id));
    for (const id of Object.keys(this.locallyTrackedUntil)) {
      if (backendIds.has(id) || this.locallyTrackedUntil[id] < now) {
        delete this.locallyTrackedUntil[id];
      }
    }

    const localMessages = this.messages.filter(item =>
      !backendIds.has(item.id) && (
        (item.id.startsWith('pending-') && (item.status === 'sending' || item.status === 'syncing')) ||
        (this.locallyTrackedUntil[item.id] || 0) > now
      )
    );
    return [...localMessages, ...messages.map(m => this.enrichMessage(m))];
  }

  private applyActionLocally(item: SupportMessage, action: string): void {
    const updatedAt = new Date().toISOString();
    if (action === 'delete') {
      this.removeLocalMessage(item.id);
      return;
    }

    const next: SupportMessage = {
      ...item,
      updated_at: updatedAt,
    };

    if (action === 'review') {
      next.status = 'reviewed';
    }

    if (action === 'forward') {
      next.status = 'forwarded';
      next.forwarded = 1;
      next.forwarded_by = this.user?.username || item.forwarded_by;
      next.forwarded_at = updatedAt;
    }

    if (action === 'reply') {
      next.status = 'replied';
      next.admin_reply = (this.replyDrafts[item.id] || '').trim();
      next.replied_by = this.user?.username || item.replied_by;
      next.replied_at = updatedAt;
    }

    this.replaceLocalMessage(item.id, this.enrichMessage(next));
  }

  private enrichMessage(item: SupportMessage): SupportMessageView {
    return {
      ...item,
      statusLabelText: this.statusLabel(item),
      formattedCreatedAt: this.formatDate(item.created_at),
      formattedRepliedAt: this.formatDate(item.replied_at),
      formattedUpdatedAt: this.formatDate(item.updated_at)
    };
  }
}
