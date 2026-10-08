import { Component, OnInit, OnDestroy, ChangeDetectorRef, ElementRef, HostListener, inject, effect } from '@angular/core';
import { Subscription } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { LucideAngularModule, Search, Bell, User, ChevronDown, HelpCircle, Settings, LogOut } from 'lucide-angular';
import { Websocket } from '../../services/websocket/websocket';
import { Notifications, ThreatNotification } from '../../services/notifications/notifications';
import { Announcement, Api } from '../../services/api/api';
import { TourService } from '../../services/tour/tour.service';
import { TenantStatusService } from '../../services/tenant-status/tenant-status';
import { SensorScopeBanner } from '../../components/sensor-scope-banner/sensor-scope-banner';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule, SensorScopeBanner],
  templateUrl: './navbar.html',
  styleUrl: './navbar.css',
})
export class Navbar implements OnInit, OnDestroy {
  SearchIcon = Search;
  BellIcon = Bell;
  UserIcon = User;
  ChevronDownIcon = ChevronDown;
  HelpCircleIcon = HelpCircle;
  SettingsIcon = Settings;
  LogOutIcon = LogOut;

  private subs = new Subscription();
  systemStatus = 'OPERATIONAL';
  searchText = '';
  showSuggestions = false;
  showUserMenu = false;
  showNotifications = false;
  alertCount = 0;
  recentAlerts: ThreatNotification[] = [];
  activeAnnouncements: Announcement[] = [];
  expandedAnnouncements = new Set<string>();

  toggleAnnouncementExpand(id: string) {
    if (this.expandedAnnouncements.has(id)) {
      this.expandedAnnouncements.delete(id);
    } else {
      this.expandedAnnouncements.add(id);
    }
  }

  isAnnouncementExpanded(id: string): boolean {
    return this.expandedAnnouncements.has(id);
  }

  suggestions = [
    { label: 'Network Logs', hint: 'View all events', route: '/analyst/logs', permission: 'logs' },
    { label: 'Alerts', hint: 'View correlation hits', route: '/analyst/alerts', permission: 'alerts' },
    { label: 'Rules', hint: 'Manage SIGMA rules', route: '/analyst/rules', permission: 'rules' },
    { label: 'Threat Intel', hint: 'IOC lookup', route: '/analyst/intel', permission: 'intel' },
    { label: 'Attack Map', hint: 'Global threat map', route: '/analyst/threat-map', permission: 'intel' },
    { label: 'Network Map', hint: 'Topology view', route: '/analyst/network-map', permission: 'network-map' },
    { label: 'System Health', hint: 'Service status', route: '/analyst/health', permission: 'health' },
    { label: 'Live Stream', hint: 'Real-time events', route: '/analyst/live', permission: 'live' },
  ];

  filteredSuggestions: any[] = [];
  private tour = inject(TourService);
  private statusInterval: ReturnType<typeof setInterval> | null = null;
  private announcementInterval: ReturnType<typeof setInterval> | null = null;

  get permittedSuggestions() {
    return this.suggestions.filter(s => this.canAccessRoute(s.route, s.permission));
  }

  get canViewAlerts() {
    return this.canOpenPermission('alerts');
  }

  get notificationCount() {
    return this.alertCount + this.unreadAnnouncementCount;
  }

  get unreadAnnouncementCount() {
    return this.activeAnnouncements.filter(announcement => !announcement.read).length;
  }

  get canShowNotifications() {
    return this.canViewAlerts || this.activeAnnouncements.length > 0;
  }

  get hasNotificationItems() {
    return this.activeAnnouncements.length > 0 || (this.canViewAlerts && this.recentAlerts.length > 0);
  }

  get canViewSettings() {
    return !this.auth.isAdmin();
  }

  get canViewTutorial() {
    const user = this.auth.getUser();
    if (!user) return false;
    return !this.auth.isAdmin() && user.role !== 'tenant_admin';
  }

  constructor(
    private auth: AuthService,
    private router: Router,
    private ws: Websocket,
    private notifications: Notifications,
    private api: Api,
    private cdr: ChangeDetectorRef,
    private el: ElementRef,
    private tenantStatusService: TenantStatusService,
  ) {
    // Mirror the shared tenant-status poll instead of running our own —
    // see refreshSystemStatus() below.
    effect(() => {
      const user = this.auth.getUser();
      if (user?.tenant_id && user.tenant_id !== 'default') {
        this.systemStatus = this.tenantStatusService.status();
        this.cdr.detectChanges();
      }
    });
  }

  startTutorial() {
    this.tour.startTour();
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent) {
    const target = event.target as HTMLElement;
    
    if (this.showNotifications) {
      const wrap = this.el.nativeElement.querySelector('.notification-wrap');
      if (wrap && !wrap.contains(target)) {
        this.showNotifications = false;
        this.cdr.detectChanges();
      }
    }
    
    if (this.showUserMenu) {
      const profileBtn = this.el.nativeElement.querySelector('.profile-button');
      if (profileBtn && !profileBtn.contains(target)) {
        this.showUserMenu = false;
        this.cdr.detectChanges();
      }
    }
  }

  ngOnInit() {
    this.refreshSystemStatus();
    this.statusInterval = setInterval(() => this.refreshSystemStatus(), 10000);
    this.loadActiveAnnouncements();
    this.announcementInterval = setInterval(() => this.loadActiveAnnouncements(), 60000);

    this.subs.add(this.ws.lastAgentStatus$.subscribe(data => {
      if (!data) return;
      this.applySystemStatus(data);
      this.cdr.detectChanges();
    }));

    this.subs.add(this.notifications.unreadCount$.subscribe(count => {
      this.alertCount = count;
      this.cdr.detectChanges();
    }));

    this.subs.add(this.notifications.alerts$.subscribe(alerts => {
      this.recentAlerts = alerts.slice(0, 5);
      this.cdr.detectChanges();
    }));
  }

  onSearchInput() {
    const term = this.searchText.toLowerCase().trim();
    if (!term) {
      this.showSuggestions = false;
      return;
    }

    this.filteredSuggestions = this.suggestions.filter(s =>
      this.canAccessRoute(s.route, s.permission) &&
      (s.label.toLowerCase().includes(term) || s.hint.toLowerCase().includes(term))
    );

    const ipPattern = /^[\d\.:a-f]+$/i;
    if (ipPattern.test(term) && this.canAccessRoute('/analyst/logs', 'logs')) {
      this.filteredSuggestions.unshift({
        label: `Search IP: ${this.searchText}`,
        hint: 'Search in Network Logs',
        route: `/analyst/logs?search=${this.searchText}`,
        permission: 'logs',
      });
    }

    if (term.length > 2 && this.canAccessRoute('/analyst/rules', 'rules')) {
      this.filteredSuggestions.push({
        label: `Search rules: "${this.searchText}"`,
        hint: 'Find SIGMA rules',
        route: `/analyst/rules?search=${this.searchText}`,
        permission: 'rules',
      });
    }

    this.showSuggestions = this.filteredSuggestions.length > 0;
    this.cdr.detectChanges();
  }

  onSearch(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      this.executeSearch();
    }
    if (event.key === 'Escape') {
      this.showSuggestions = false;
    }
  }

  executeSearch() {
    const term = this.searchText.toLowerCase().trim();
    if (!term) return;

    if (term.match(/^\d+\.\d+\.\d+\.\d+/) || term.includes(':')) {
      this.navigateIfAllowed('/analyst/logs', 'logs', { search: this.searchText });
    } else if (term.includes('alert') || term.includes('hit')) {
      this.navigateIfAllowed('/analyst/alerts', 'alerts');
    } else if (term.includes('rule') || term.includes('sigma')) {
      this.navigateIfAllowed('/analyst/rules', 'rules');
    } else if (term.includes('threat') || term.includes('intel') || term.includes('ioc')) {
      this.navigateIfAllowed('/analyst/intel', 'intel');
    } else if (term.includes('health') || term.includes('status')) {
      this.navigateIfAllowed('/analyst/health', 'health');
    } else if (term.includes('live') || term.includes('stream')) {
      this.navigateIfAllowed('/analyst/live', 'live');
    } else if (term.includes('map') || term.includes('topology')) {
      this.navigateIfAllowed('/analyst/network-map', 'network-map');
    } else {
      this.navigateIfAllowed('/analyst/logs', 'logs', { search: this.searchText });
    }

    this.showSuggestions = false;
    this.searchText = '';
  }

  selectSuggestion(suggestion: any) {
    if (this.canAccessRoute(suggestion.route, suggestion.permission)) {
      this.router.navigateByUrl(suggestion.route);
    } else {
      this.router.navigate([this.auth.getDefaultRoute()]);
    }
    this.showSuggestions = false;
    this.searchText = '';
  }

  openNotifications() {
    this.showNotifications = !this.showNotifications;
    if (this.showNotifications) {
      this.loadActiveAnnouncements();
      this.notifications.markAllRead();
    }
    this.showSuggestions = false;
    this.cdr.detectChanges();
  }


  viewThreatIntel() {
    this.showNotifications = false;
    this.navigateIfAllowed('/analyst/intel', 'intel');
  }

  announcementTypeLabel(type: string | undefined) {
    switch (type) {
      case 'maintenance':
        return 'Maintenance';
      case 'update':
        return 'Platform Update';
      case 'critical':
        return 'Critical';
      default:
        return 'Information';
    }
  }

  announcementTypeClass(type: string | undefined) {
    return `announcement-${type || 'info'}`;
  }

  closeSearch() {
    setTimeout(() => {
      this.showSuggestions = false;
      this.cdr.detectChanges();
    }, 200);
  }

  get currentUser() {
    return this.auth.getUser();
  }

  get showSensorScope(): boolean {
    const role = this.currentUser?.role;
    return role === 'analyst' || role === 'senior_analyst' || role === 'viewer';
  }

  get sensorIds(): string[] {
    return this.auth.getSensorIds() || [];
  }

  goToSettings() {
    this.showUserMenu = false;
    if (this.auth.isTenantAdmin()) {
      this.router.navigate(['/tenant-admin/settings']);
    } else {
      this.router.navigate(['/analyst/settings']);
    }
  }

  goToSupport() {
    this.showUserMenu = false;
    if (this.auth.isAdmin()) {
      this.router.navigate(['/admin/support']);
    } else if (this.auth.isTenantAdmin()) {
      this.router.navigate(['/tenant-admin/support']);
    } else {
      this.router.navigate(['/analyst/support']);
    }
  }

  logout() {
    this.showUserMenu = false;
    this.auth.logout();
  }

  ngOnDestroy() {
    if (this.statusInterval) clearInterval(this.statusInterval);
    if (this.announcementInterval) clearInterval(this.announcementInterval);
    this.subs.unsubscribe();
  }

  private canOpenPermission(permission: string) {
    return this.auth.hasPermission(permission);
  }

  private canAccessRoute(route: string, permission: string): boolean {
    const user = this.auth.getUser();
    if (!user) return false;

    const analystRoutes = ['/analyst/logs', '/analyst/alerts', '/analyst/rules', '/analyst/intel', '/analyst/network-map', '/analyst/health', '/analyst/live', '/analyst/threat-map'];
    if (analystRoutes.includes(route) || route.startsWith('/analyst/logs?') || route.startsWith('/analyst/rules?')) {
      if (this.auth.isAdmin() || user.role === 'tenant_admin') {
        return false;
      }
    }

    return this.auth.hasPermission(permission);
  }

  private refreshSystemStatus() {
    const user = this.auth.getUser();
    if (user?.tenant_id && user.tenant_id !== 'default') {
      // Shared poll (also used by tenant-admin-layout) — idempotent, only
      // actually starts the interval once. The effect() in the constructor
      // mirrors its result into systemStatus.
      this.tenantStatusService.startPolling();
      return;
    }

    // getDashboardStats() hits /api/health, which reports real platform health
    // (Kafka + ClickHouse connectivity) - not getAgentStatus(), which checks for
    // a local on-prem capture agent (Zeek/Suricata/Vector, install-customer.sh
    // only) that doesn't exist on a cloud deployment with remote sensors. That
    // mismatch made this always read DEGRADED on cloud installs regardless of
    // whether the platform was actually healthy.
    this.api.getDashboardStats().subscribe({
      next: data => {
        this.applySystemStatus(data);
        this.cdr.detectChanges();
      },
      // Without this, any failure (401 on an already-cleared session right
      // as logout navigates away, a network blip, etc.) surfaces as an
      // uncaught console error every 10s instead of being handled quietly -
      // matches the pattern already used by loadActiveAnnouncements below.
      error: () => {},
    });
  }

  private loadActiveAnnouncements() {
    this.api.getActiveAnnouncements().subscribe({
      next: announcements => {
        this.activeAnnouncements = announcements;
        if (this.showNotifications) {
          this.markUnreadAnnouncementsRead();
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.activeAnnouncements = [];
        this.cdr.detectChanges();
      },
    });
  }

  private markUnreadAnnouncementsRead() {
    const unread = this.activeAnnouncements.filter(announcement => !announcement.read);
    if (unread.length === 0) return;

    unread.forEach(announcement => {
      announcement.read = true;
      this.api.markAnnouncementRead(announcement.id).subscribe({
        error: () => {
          announcement.read = false;
          this.cdr.detectChanges();
        },
      });
    });
    this.cdr.detectChanges();
  }


  private applySystemStatus(data: any) {
    const kafkaRunning      = this.isRunning(data?.services?.kafka);
    const clickhouseRunning = this.isRunning(data?.services?.clickhouse);
    // Both are core to every deployment model (cloud and on-prem) - unlike the
    // local capture agent, they're always meaningful to check here.
    this.systemStatus = kafkaRunning && clickhouseRunning ? 'OPERATIONAL' : 'DEGRADED';
  }

  private isRunning(status: unknown) {
    const value = String(status || '').toLowerCase().trim();
    // 'unknown' is allowed because external sensors may not report process state; we rely on heartbeats.
    if (['running', 'healthy', 'ok', 'up', 'active', 'started', 'unknown'].includes(value)) return true;
    return /^\d+$/.test(value);
  }

  private isRecentlySeen(value: string | undefined) {
    if (!value) return false;
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const timestamp = new Date(withTimezone).getTime();
    return !Number.isNaN(timestamp) && Date.now() - timestamp <= 2 * 60 * 1000;
  }

  private navigateIfAllowed(route: string, permission: string, queryParams?: Record<string, string>) {
    if (!this.canAccessRoute(route, permission)) {
      this.router.navigate([this.auth.getDefaultRoute()]);
      return;
    }

    this.router.navigate([route], queryParams ? { queryParams } : undefined);
  }
}
