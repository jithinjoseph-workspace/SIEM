import { Injectable, signal } from '@angular/core';

/**
 * One shared wall-clock, instead of every admin page running its own
 * identical setInterval + toLocaleTimeString/toLocaleDateString pair.
 * Exposed as signals so OnPush components update automatically just by
 * reading `clock.currentTime()` / `clock.currentDate()` in their template
 * — no manual ChangeDetectorRef.detectChanges() needed.
 */
@Injectable({ providedIn: 'root' })
export class ClockService {
  readonly currentTime = signal(ClockService.formatTime(new Date()));
  readonly currentDate = signal(ClockService.formatDate(new Date()));

  constructor() {
    setInterval(() => {
      const now = new Date();
      this.currentTime.set(ClockService.formatTime(now));
      this.currentDate.set(ClockService.formatDate(now));
    }, 1000);
  }

  private static formatTime(d: Date): string {
    return d.toLocaleTimeString('en-US', { hour12: false });
  }

  private static formatDate(d: Date): string {
    return d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
  }
}
