import { Injectable, signal } from '@angular/core';
import { Api } from '../api/api';
import { AuthService } from '../auth/auth';

/**
 * Single shared poll for tenant pipeline/platform health, computed from
 * getSensorKeys()+getDashboardStats(). Both the navbar and the tenant-admin
 * layout need this value simultaneously (navbar is always mounted; the
 * tenant-admin layout is mounted underneath it on /tenant-admin/* routes) —
 * they used to each run their own independent 10s poll with the identical
 * two chained API calls, doubling real request volume for the entire
 * session. Centralized here so there's exactly one poll no matter how many
 * components display the result.
 */
@Injectable({ providedIn: 'root' })
export class TenantStatusService {
  readonly status = signal<'OPERATIONAL' | 'DEGRADED' | 'CHECKING...'>('CHECKING...');
  /** Raw sensor-keys response from the shared poll, already tenant-scoped by
   *  the backend. Other components (e.g. the tenant-admin Users page) should
   *  read this reactively instead of calling getSensorKeys() themselves -
   *  that used to happen in parallel with this poll's own call, a genuinely
   *  redundant fetch on every page load. */
  readonly sensorKeys = signal<any[]>([]);
  /** True once the first fetch completes (success or error) - lets consumers
   *  tell "not fetched yet" apart from "fetched, tenant genuinely has zero
   *  sensors", since sensorKeys() alone reads as [] in both cases. */
  readonly sensorKeysLoaded = signal(false);

  private pollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private api: Api, private auth: AuthService) {}

  startPolling() {
    if (this.pollTimer) return;
    this.refresh();
    this.pollTimer = setInterval(() => this.refresh(), 10000);
  }

  /** Pause polling — e.g. while a platform update is in progress and status would otherwise flap. */
  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private isRunning(status: unknown): boolean {
    const value = String(status || '').toLowerCase().trim();
    if (['running', 'healthy', 'ok', 'up', 'active', 'started', 'unknown'].includes(value)) return true;
    return /^\d+$/.test(value);
  }

  private refresh() {
    this.api.getSensorKeys().subscribe({
      next: (sensors: any[]) => {
        this.sensorKeys.set(sensors);
        this.sensorKeysLoaded.set(true);
        const user = this.auth.getUser();
        const mySensorIds = user?.sensor_ids || [];
        // Backend already scopes sensors to the tenant. If the user is a
        // restricted analyst, filter down to their assigned sensors.
        const isRestrictedAnalyst = user?.role !== 'tenant_admin' && user?.role !== 'admin' && mySensorIds.length > 0;
        const mySensors = isRestrictedAnalyst
          ? sensors.filter((s: any) => mySensorIds.includes(s.key_prefix))
          : sensors;

        const healthyPipeline = mySensors.length === 0
          // Zero sensors registered — assume operational rather than showing
          // degraded for a blank account.
          || mySensors.some((s: any) =>
            s.active !== false &&
            (this.isRunning(s['agent-z']) || this.isRunning(s['agent-s']) || this.isRunning(s.vector))
          );

        this.api.getDashboardStats().subscribe({
          next: (data: any) => {
            const services = data?.services || {};
            const platformHealthy =
              this.isRunning(services.kafka) &&
              this.isRunning(services.clickhouse) &&
              this.isRunning(services.engine || 'running');
            this.status.set(healthyPipeline && platformHealthy ? 'OPERATIONAL' : 'DEGRADED');
          },
          error: () => this.status.set('DEGRADED'),
        });
      },
      error: () => {
        this.status.set('DEGRADED');
        this.sensorKeysLoaded.set(true);
      },
    });
  }
}
