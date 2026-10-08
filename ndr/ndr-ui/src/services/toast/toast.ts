import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface Toast {
  id: string;
  severity: 'CRITICAL' | 'HIGH';
  message: string;
  src_ip: string;
  dst_ip: string;
  score: number;
  hits: number;
  tags: string[];
  timestamp: string;
  /** Unique key used to merge duplicate flows while the toast is visible */
  flowKey: string;
}

const MAX_VISIBLE = 3;
const AUTO_DISMISS_MS = 5000;

@Injectable({
  providedIn: 'root',
})
export class ToastService {
  private readonly _toasts$ = new BehaviorSubject<Toast[]>([]);
  readonly toasts$ = this._toasts$.asObservable();

  /** timers keyed by toast.id */
  private timers = new Map<string, ReturnType<typeof setTimeout>>();

  add(toast: Omit<Toast, 'id'>): void {
    const current = [...this._toasts$.value];

    // ── Dedup: if this flow is already on screen, update in-place ──────────
    const existingIdx = current.findIndex(t => t.flowKey === toast.flowKey);
    if (existingIdx !== -1) {
      const existing = current[existingIdx];
      // Reset auto-dismiss timer
      this._clearTimer(existing.id);
      const updated: Toast = {
        ...existing,
        score:     Math.max(existing.score, toast.score),
        hits:      existing.hits + 1,
        tags:      Array.from(new Set([...existing.tags, ...toast.tags])),
        timestamp: toast.timestamp,
        severity:  toast.severity,
        message:   toast.message,
      };
      current.splice(existingIdx, 1, updated);
      this._toasts$.next([...current]);
      this._scheduleAutoDismiss(updated.id);
      return;
    }

    // ── Cap: if already at max, drop the oldest (index 0) ─────────────────
    if (current.length >= MAX_VISIBLE) {
      const oldest = current[0];
      this._clearTimer(oldest.id);
      current.shift();
    }

    const newToast: Toast = {
      ...toast,
      id: `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    };

    this._toasts$.next([...current, newToast]);
    this._scheduleAutoDismiss(newToast.id);
  }

  dismiss(id: string): void {
    this._clearTimer(id);
    const updated = this._toasts$.value.filter(t => t.id !== id);
    this._toasts$.next(updated);
  }

  private _scheduleAutoDismiss(id: string): void {
    const timer = setTimeout(() => this.dismiss(id), AUTO_DISMISS_MS);
    this.timers.set(id, timer);
  }

  private _clearTimer(id: string): void {
    const timer = this.timers.get(id);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
  }
}
