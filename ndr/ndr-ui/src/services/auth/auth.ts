import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, of, tap, Subscription } from 'rxjs';
import { Websocket } from '../websocket/websocket';
import { ConfigService } from '../config/config.service';

import { reportRxjsError } from '../error-reporter/error-reporter';
@Injectable({ providedIn: 'root' })
export class AuthService implements OnDestroy {
  private baseUrl = '/api';
  private USER_KEY = 'ndr_user';

  /**
   * How often to poll /api/auth/me to detect account blocking.
   * 30 seconds is a deliberate balance: quick enough to evict a blocked user
   * promptly, low enough to not meaningfully increase server load.
   */
  private readonly SESSION_POLL_MS = 30_000;
  private sessionPollInterval: ReturnType<typeof setInterval> | null = null;
  private sessionPollSub: Subscription | null = null;

  /** Timestamp (ms) of last successful user data write — used to skip a redundant
   *  /api/auth/me round-trip in authGuard immediately after login. */
  private userDataFreshAt = 0;

  private readonly defaultRouteByPermission: Record<string, string> = {
    dashboard: '/analyst/dashboard',
    alerts: '/analyst/alerts',
    logs: '/analyst/logs',
    live: '/analyst/live',
    'network-map': '/analyst/network-map',
    rules: '/analyst/rules',
    intel: '/analyst/intel',
    health: '/analyst/health',
    setup: '/analyst/setup',
    soar: '/analyst/soar',
    settings: '/analyst/settings',
    evidence: '/analyst/evidence',
    assets: '/analyst/assets',
    'ai-activity': '/ai-activity',
    'ai-report': '/ai-report',
  };

  constructor(
    private http: HttpClient,
    private router: Router,
    private ws: Websocket,
    private config: ConfigService,
  ) { }

  ngOnDestroy(): void {
    this.stopSessionPoll();
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/login`, {
      username, password
    }).pipe(
      tap((res: any) => {
        if (res.user) {
          // Token stays only in the httpOnly cookie — never in localStorage.
          localStorage.setItem(this.USER_KEY, JSON.stringify({
            ...res.user,
            permissions: this.normalizePermissions(res.user?.permissions),
            sensor_ids: res.user.sensor_ids ?? [],
            expires_at: res.user.expires_at,
          }));
          this.userDataFreshAt = Date.now();
        }
      })
    );
  }

  /** True if user data was written within the last 10 seconds — authGuard can
   *  skip the /api/auth/me round-trip when this returns true. */
  isUserDataFresh(): boolean {
    return Date.now() - this.userDataFreshAt < 10_000;
  }

  /** Check if a username exists in the database (no auth required). */
  checkUsername(username: string): Observable<{ exists: boolean }> {
    return this.http.get<{ exists: boolean }>(
      `${this.baseUrl}/auth/check-username`,
      { params: { username } }
    );
  }


  logout() {
    // Stop polling before clearing state so any in-flight poll doesn't restart it
    this.stopSessionPoll();
    this.ws.disconnect();
    localStorage.removeItem(this.USER_KEY);
    sessionStorage.clear();
    // Tell the backend to expire the httpOnly cookie (fire-and-forget;
    // navigation happens regardless of whether the request succeeds).
    this.http.post(`${this.baseUrl}/auth/logout`, {}, { withCredentials: true })
      .subscribe({ error: reportRxjsError });
    this.router.navigate(['/login'], { replaceUrl: true });
  }

  refreshUser(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/me`).pipe(
      tap((res: any) => {
        if (res.status === 'ok' && res.user) {
          // Spread existing stored data first so sensor_ids / expires_at
          // (written at login) are preserved across polls — /api/auth/me
          // does not re-send those fields.
          const current = this.getUser() ?? {};
          localStorage.setItem(this.USER_KEY, JSON.stringify({
            ...current,
            ...res.user,
            permissions: this.normalizePermissions(res.user.permissions),
          }));
          this.userDataFreshAt = Date.now();
        }
        // If backend returns USER_DISABLED via get_me (HTTP 200 with error body),
        // the authGuard already calls logout() when status !== 'ok'.
        // The auth-interceptor handles the 403 path (from auth_middleware).
      })
    );
  }

  getUser(): any {
    const u = localStorage.getItem(this.USER_KEY);
    if (!u) return null;

    try {
      const user = JSON.parse(u);
      return {
        ...user,
        permissions: this.normalizePermissions(user?.permissions),
      };
    } catch {
      return null;
    }
  }

  isLoggedIn(): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (!user.expires_at) return true; // legacy sessions without expires_at stored
    return user.expires_at > Date.now() / 1000;
  }

  /** Returns milliseconds until the session expires. Negative means already expired. */
  getTokenExpiresInMs(): number {
    const user = this.getUser();
    if (!user?.expires_at) return -1;
    return (user.expires_at * 1000) - Date.now();
  }

  isAdmin(): boolean {
    const role = this.getUser()?.role;
    return role === 'admin' || role === 'super_admin';
  }

  isTenantAdmin(): boolean {
    return this.getUser()?.role === 'tenant_admin';
  }

  /**
   * Returns the sensor IDs the current user is scoped to.
   * Reads directly from the JWT payload since sensor_ids are baked in at login.
   * Returns [] for unrestricted users (admins / tenant_admins) or when no token exists.
   */
  getSensorIds(): string[] {
    return this.getUser()?.sensor_ids ?? [];
  }

  isTenantAiEnabled(): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    return user.ai_enabled !== false;
  }

  // Returns features licensed for this tenant (stored in user session after login).
  // super_admin always gets all features; others read from the session features array.
  // When the JWT has no features field, we fall back to the product mode reported
  // by nginx (/product-config.json loaded at startup by ConfigService).
  hasFeature(feature: string): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    const feats = user.features as string[] | undefined | null;
    // Only trust JWT features if the array is non-empty; empty = not yet assigned, fall through
    if (feats && feats.length > 0) return feats.includes(feature);
    // No features set in JWT — derive from installed product mode
    if (feature === 'ndr')  return this.config.hasNdr();
    if (feature === 'siem') return this.config.hasSiem();
    return false;
  }

  getTenantFeatures(): string[] {
    const user = this.getUser();
    if (!user) return this.config.hasNdr() ? ['ndr'] : ['siem'];
    if (user.role === 'super_admin') return ['ndr', 'siem', 'ai', 'soar'];
    if (user.features) return user.features as string[];
    const derived: string[] = [];
    if (this.config.hasNdr())  derived.push('ndr');
    if (this.config.hasSiem()) derived.push('siem');
    return derived.length ? derived : ['ndr'];
  }

  hasPermission(permission: string): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (this.isAdmin() || user.role === 'tenant_admin') return true;

    return this.normalizePermissions(user.permissions).includes(permission);
  }

  getDefaultRoute(): string {
    const user = this.getUser();
    if (!user) return '/login';
    if (this.isAdmin()) return '/admin';
    if (user.role === 'tenant_admin') return '/tenant-admin';

    // SIEM-only installs default to SIEM dashboard
    if (this.config.hasSiem() && !this.config.hasNdr()) return '/siem/dashboard';

    const permissions = this.normalizePermissions(user.permissions);
    const firstPermission = permissions.find(permission => this.defaultRouteByPermission[permission]);
    return firstPermission ? this.defaultRouteByPermission[firstPermission] : '/settings';
  }

  normalizePermissions(value: unknown): string[] {
    const rawPermissions = Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(',')
        : [];

    return Array.from(new Set(rawPermissions
      .map(permission => String(permission).trim())
      .filter(Boolean)
      .map(permission => permission.endsWith(':view')
        ? permission.replace(':view', '')
        : permission
      )
      .map(permission => permission === 'network' ? 'network-map' : permission)));
  }

  // ── Session Poll ─────────────────────────────────────────────────────────

  /**
   * Start a recurring poll of /api/auth/me every SESSION_POLL_MS milliseconds.
   *
   * This is the primary mechanism for detecting a live-session block:
   *   - If the user is blocked, the backend returns { code: "USER_DISABLED" }
   *     which the authGuard's refreshUser() call treats as a non-ok status
   *     and calls logout().
   *   - Additionally auth_middleware returns HTTP 403 on any other API call,
   *     which the auth-interceptor catches and calls logout() for.
   *
   * Only meaningful for analyst/viewer roles — admins are never blocked.
   * Safe to call multiple times; only one interval is ever active.
   */
  startSessionPoll(): void {
    if (this.sessionPollInterval !== null) return; // already running

    this.sessionPollInterval = setInterval(() => {
      if (!this.isLoggedIn()) {
        // Token expired; clean up instead of spamming the backend
        this.stopSessionPoll();
        return;
      }

      // Reuse the same observable that authGuard uses.
      // The tap() inside refreshUser() updates localStorage on success.
      // On error: auth-interceptor handles 403 USER_DISABLED → logout().
      // On non-ok status (USER_DISABLED via 200): authGuard logic applies
      // on the next navigation; for immediate eviction we check here too.
      this.sessionPollSub?.unsubscribe();
      this.sessionPollSub = this.refreshUser().subscribe({
        next: (res: any) => {
          if (res.status !== 'ok') {
            // Covers USER_DISABLED returned as HTTP 200 from get_me
            this.logout();
          }
        },
        error: () => {
          // HTTP errors (401/403) are already handled by auth-interceptor.
          // No additional action needed here.
        }
      });
    }, this.SESSION_POLL_MS);
  }

  /**
   * Stop the session poll and clean up subscriptions.
   * Called automatically by logout() and ngOnDestroy().
   */
  stopSessionPoll(): void {
    if (this.sessionPollInterval !== null) {
      clearInterval(this.sessionPollInterval);
      this.sessionPollInterval = null;
    }
    this.sessionPollSub?.unsubscribe();
    this.sessionPollSub = null;
  }
}
