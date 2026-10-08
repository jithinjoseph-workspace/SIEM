import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectorRef,
  ChangeDetectionStrategy,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { ToastService, Toast } from '../../services/toast/toast';

@Component({
  selector: 'app-toast-container',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './toast-container.html',
  styleUrl: './toast-container.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ToastContainer implements OnInit, OnDestroy {
  toasts: Toast[] = [];

  private sub!: Subscription;

  constructor(
    private toastService: ToastService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.sub = this.toastService.toasts$.subscribe(toasts => {
      this.toasts = toasts;
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }

  dismiss(id: string): void {
    this.toastService.dismiss(id);
  }

  trackById(_: number, toast: Toast): string {
    return toast.id;
  }

  severityLabel(severity: string): string {
    return severity === 'CRITICAL' ? '⬛ CRITICAL' : '⬛ HIGH';
  }

  primaryTag(toast: Toast): string {
    return toast.tags.find(t => t.startsWith('attack.')) ?? toast.tags[0] ?? '';
  }

  extraTagCount(toast: Toast): number {
    const filtered = toast.tags.filter(t => t.startsWith('attack.'));
    return Math.max(0, (filtered.length > 0 ? filtered.length : toast.tags.length) - 1);
  }
}
