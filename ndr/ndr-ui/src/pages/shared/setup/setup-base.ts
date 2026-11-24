import { Directive, HostListener, OnDestroy, OnInit, ChangeDetectorRef, signal, computed } from '@angular/core';
import { Router } from '@angular/router';
import {
  Activity,
  Copy,
  KeyRound,
  Plus,
  Play,
  RefreshCcw,
  Server,
  Settings,
  ShieldCheck,
  Square,
  AlertTriangle,
  Monitor,
  Link,
  ClipboardList,
  MoreVertical,
  Wifi,
  WifiOff,
  Clock,
  X,
  Ban,
} from 'lucide-angular';
import { Subscription, timer } from 'rxjs';
import { filter } from 'rxjs/operators';
import { Api, SensorControlCommand, SensorKey } from '../../../services/api/api';
import { Websocket } from '../../../services/websocket/websocket';
import { AuthService } from '../../../services/auth/auth';

export type SetupTab = 'local' | 'external';
export type ExternalServiceStatus = 'running' | 'stopped' | 'restarting' | 'unknown';

export interface ExternalSensorCard extends SensorKey {
  displayName: string;
  hostname: string;
  interface: string;
  os: string;
  'agent-z': ExternalServiceStatus;
  'agent-s': ExternalServiceStatus;
  vector: ExternalServiceStatus;
  online: boolean;
}

@Directive()
export abstract class SetupBase implements OnInit, OnDestroy {
  interfaces: string[] = [];
  selectedInterface = '';
  status = signal<string>('Ready');
  agentZStatus = signal<string>('stopped');
  agentSStatus = signal<string>('stopped');
  vectorStatus = signal<string>('stopped');
  arkimeStatus = signal<string>('stopped');
  activeTab: SetupTab = 'local';
  externalSensors: ExternalSensorCard[] = [];
  externalLoading = false;
  externalError = '';
  externalActionMessage = '';
  pendingExternalCommand: { sensorId: string; command: SensorControlCommand } | null = null;
  // Signals, not plain fields: this app has no zone.js, so a plain field changed
  // inside an HTTP callback does not redraw the view on its own - the dialog
  // sat on "Revoking..." until an unrelated click happened to trigger a redraw.
  revokingSensorId = signal<string | null>(null);
  pendingRevokeSensor = signal<ExternalSensorCard | null>(null);
  showAddSensorModal = false;
  newSensorName = '';
  creatingSensor = false;
  createdSensorKey: SensorKey | null = null;
  installCommand = '';
  keyCopied = false;
  commandCopied = false;
  cloudUrl = this.detectCloudUrl();
  customServerUrl = '';
  isLocalhostUrl = false;

  showErrorModal = false;
  errorTitle = '';
  errorMessage = '';

  protected subs: Subscription[] = [];
  protected currentRole = '';
  protected currentTenantId = '';

  /** Where to send a user who fails the tenant/role gate in ngOnInit. Section-specific. */
  protected abstract readonly unauthorizedRedirectPath: string;

  SettingsIcon = Settings;
  CopyIcon = Copy;
  KeyIcon = KeyRound;
  PlusIcon = Plus;
  PlayIcon = Play;
  StopIcon = Square;
  RefreshIcon = RefreshCcw;
  ShieldIcon = ShieldCheck;
  ActivityIcon = Activity;
  ServerIcon = Server;
  AlertIcon = AlertTriangle;
  MonitorIcon = Monitor;
  LinkIcon = Link;
  ClipboardListIcon = ClipboardList;
  MoreVerticalIcon = MoreVertical;
  WifiIcon = Wifi;
  WifiOffIcon = WifiOff;
  ClockIcon = Clock;
  XIcon = X;
  BanIcon = Ban;

  constructor(
    protected api: Api,
    protected ws: Websocket,
    protected cdr: ChangeDetectorRef,
    protected auth: AuthService,
    protected router: Router
  ) {}

  ngOnInit() {
    const user = this.auth.getUser();
    if (user?.tenant_id !== 'default' && user?.role !== 'tenant_admin') {
      this.router.navigate([this.unauthorizedRedirectPath]);
      return;
    }

    this.currentRole = user?.role || '';
    this.currentTenantId = user?.tenant_id || '';
    this.activeTab =
      this.currentRole === 'tenant_admin' && this.currentTenantId !== 'default'
        ? 'external'
        : 'local';

    if (this.canViewLocalSensor) {
      this.loadLocalSensorSetup();
    }

    if (this.canViewExternalSensors) {
      this.loadExternalSensors();
      this.subs.push(
        timer(30000, 30000).subscribe(() => this.loadExternalSensors(true))
      );
    }
  }

  ngOnDestroy() {
    this.subs.forEach(subscription => subscription.unsubscribe());
  }

  get canViewExternalSensors(): boolean {
    return this.currentRole === 'super_admin' || this.currentRole === 'tenant_admin';
  }

  get canViewLocalSensor(): boolean {
    return this.currentTenantId === 'default';
  }

  get isDefaultTenant(): boolean {
    return this.currentTenantId === 'default';
  }

  localRunningCount = computed(() =>
    [this.agentZStatus(), this.agentSStatus(), this.vectorStatus(), this.arkimeStatus()]
      .filter(s => s === 'running').length
  );

  get externalOnlineCount(): number {
    return this.externalSensors.filter(sensor => sensor.online).length;
  }

  get externalOfflineCount(): number {
    return Math.max(this.externalSensors.length - this.externalOnlineCount, 0);
  }

  get tenantDisplayName(): string {
    return this.currentTenantId || 'Tenant';
  }

  get summaryActive(): boolean {
    return this.activeTab === 'local'
      ? this.status() === 'Running'
      : this.externalOnlineCount > 0;
  }

  get summaryTitle(): string {
    if (this.activeTab === 'local') {
      return this.status();
    }

    if (!this.canViewExternalSensors) {
      return 'Unavailable';
    }

    if (this.externalLoading) {
      return 'Loading...';
    }

    if (!this.externalSensors.length) {
      return 'No Sensors';
    }

    return `${this.externalOnlineCount}/${this.externalSensors.length} Online`;
  }

  get summaryDetail(): string {
    if (this.activeTab === 'local') {
      return this.selectedInterface || 'No interface selected';
    }

    if (!this.canViewExternalSensors) {
      return 'Tenant admin or super admin required';
    }

    return this.externalSensors.length
      ? 'External sensor command queue ready'
      : 'No registered external sensors';
  }

  updateStatus(data: any) {
    if (data['agent-z'] != null) this.agentZStatus.set(this.normalizeStatus(data['agent-z']));
    if (data['agent-s'] != null) this.agentSStatus.set(this.normalizeStatus(data['agent-s']));
    if (data.vector != null)     this.vectorStatus.set(this.normalizeStatus(data.vector));
    if (data.arkime != null)     this.arkimeStatus.set(this.normalizeStatus(data.arkime));
    this.selectedInterface = data.interface || this.selectedInterface;

    if (
      this.agentZStatus() === 'running' &&
      this.agentSStatus() === 'running' &&
      this.vectorStatus() === 'running' &&
      this.arkimeStatus() === 'running'
    ) {
      this.status.set('Running');
    } else if (this.status() !== 'Starting...' && this.status() !== 'Stopping...') {
      this.status.set('Stopped');
    }
  }

  showError(title: string, message: string) {
    this.errorTitle = title;
    this.errorMessage = message;
    this.showErrorModal = true;
    this.cdr.detectChanges();
  }

  selectTab(tab: SetupTab) {
    if (tab === 'local' && !this.canViewLocalSensor) {
      return;
    }

    this.activeTab = tab;
  }

  applyInterface() {
    this.api.setInterface(this.selectedInterface).subscribe({
      next: () => { /* interface applied silently */ },
      error: (error) => {
        this.showError('Apply Interface Failed', error?.error?.message || 'Could not apply interface to local sensor. Please verify connection and try again.');
      }
    });
  }

  startMonitoring() {
    this.status.set('Starting...');
    this.api.startServices().subscribe({
      next: () => {
        this.pollStatus('Running');
      },
      error: (error) => {
        this.status.set('Stopped');
        this.cdr.detectChanges();
        this.showError('Start Monitoring Failed', error?.error?.message || 'Failed to start local sensor monitoring services (Agent-Z, Agent-S, Telemetry Pipeline). Please check host status.');
      },
    });
  }

  stopMonitoring() {
    this.status.set('Stopping...');
    this.api.stopServices().subscribe({
      next: () => {
        this.pollStatus('Stopped');
      },
      error: (error) => {
        this.status.set('Running');
        this.cdr.detectChanges();
        this.showError('Stop Monitoring Failed', error?.error?.message || 'Failed to stop local sensor monitoring services. Please verify status on host.');
      },
    });
  }

  controlExternalSensor(sensor: ExternalSensorCard, command: SensorControlCommand) {
    const sensorName = this.getSensorDisplayName(sensor);
    this.pendingExternalCommand = {
      sensorId: sensor.key_prefix,
      command,
    };
    this.externalActionMessage = '';
    this.externalError = '';

    this.api.controlSensor(command, sensor.tenant_id, sensor.key_prefix).subscribe({
      next: () => {
        this.externalActionMessage = `${this.getCommandLabel(command)} queued for ${sensorName}.`;
        this.pendingExternalCommand = null;
        this.loadExternalSensors(true);
        this.cdr.detectChanges();
      },
      error: error => {
        this.externalError =
          error?.error?.message || `Unable to ${command} ${sensorName}.`;
        this.pendingExternalCommand = null;
        this.cdr.detectChanges();
      },
    });
  }

  /** Deactivates the sensor's key. Unlike start/stop/restart this does not need
   *  the sensor to be online - it is the way to cut off a sensor that is stuck,
   *  offline, or misbehaving. The backend only lets tenant_admin/super_admin do
   *  this, and a tenant_admin only for their own tenant's keys. */
  askRevokeExternalSensor(sensor: ExternalSensorCard) {
    if (!this.canViewExternalSensors || this.revokingSensorId()) {
      return;
    }
    this.pendingRevokeSensor.set(sensor);
  }

  @HostListener('document:keydown.escape')
  cancelRevokeExternalSensor() {
    // Ignored while the request is in flight so the dialog can't vanish mid-revoke.
    if (this.revokingSensorId()) {
      return;
    }
    this.pendingRevokeSensor.set(null);
  }

  confirmRevokeExternalSensor() {
    const sensor = this.pendingRevokeSensor();
    if (!sensor || this.revokingSensorId()) {
      return;
    }
    const sensorName = this.getSensorDisplayName(sensor);

    this.revokingSensorId.set(sensor.id);
    this.externalActionMessage = '';
    this.externalError = '';

    this.api.revokeSensorKey(sensor.id).subscribe({
      next: response => {
        this.revokingSensorId.set(null);
        this.pendingRevokeSensor.set(null);
        if (response?.status === 'ok') {
          this.externalActionMessage = `${sensorName} revoked.`;
          this.loadExternalSensors(true);
        } else {
          // The API reports refusals (forbidden, not found) as HTTP 200 with status "error".
          this.externalError = response?.message || `Unable to revoke ${sensorName}.`;
        }
        this.cdr.detectChanges();
      },
      error: error => {
        this.revokingSensorId.set(null);
        this.pendingRevokeSensor.set(null);
        this.externalError = error?.error?.message || `Unable to revoke ${sensorName}.`;
        this.cdr.detectChanges();
      },
    });
  }

  openAddSensorModal() {
    this.newSensorName = '';
    this.createdSensorKey = null;
    this.installCommand = '';
    this.externalError = '';
    this.externalActionMessage = '';
    this.isLocalhostUrl = this.cloudUrl.includes('localhost') || this.cloudUrl.includes('127.0.0.1');
    this.customServerUrl = this.isLocalhostUrl ? '' : this.cloudUrl;
    this.showAddSensorModal = true;
  }

  createExternalSensorKey() {
    const name = this.newSensorName.trim();
    if (!name) {
      this.externalError = 'Sensor name is required.';
      return;
    }

    this.creatingSensor = true;
    this.externalError = '';
    this.externalActionMessage = '';

    this.api.createSensorKey(this.currentTenantId, name).subscribe({
      next: response => {
        this.creatingSensor = false;

        if (response?.status === 'ok' && response.key) {
          this.createdSensorKey = {
            id: response.id,
            key: response.key,
            key_prefix: response.key.slice(0, 16),
            tenant_id: this.currentTenantId,
            name,
            active: true,
            created_at: new Date().toISOString(),
            last_seen: '',
          };
          this.installCommand = this.buildInstallCommand(response.key);
          this.newSensorName = '';
          this.externalActionMessage = 'Sensor key generated. Copy it before closing.';
          this.loadExternalSensors(true);
        } else {
          this.externalError = response?.message || 'Failed to generate sensor key.';
        }

        this.cdr.detectChanges();
      },
      error: error => {
        this.creatingSensor = false;
        this.externalError = error?.error?.message || 'Failed to generate sensor key.';
        this.cdr.detectChanges();
      },
    });
  }

  copyCreatedSensorKey() {
    if (this.createdSensorKey?.key) {
      this.keyCopied = false;
      navigator.clipboard.writeText(this.createdSensorKey.key).then(
        () => {
          this.keyCopied = true;
          this.externalActionMessage = 'Sensor key copied.';
          this.externalError = '';
          this.cdr.detectChanges();
          setTimeout(() => {
            this.keyCopied = false;
            this.cdr.detectChanges();
          }, 2500);
        },
        () => {
          this.externalError = 'Failed to copy to clipboard.';
          this.cdr.detectChanges();
        }
      );
    }
  }

  copyInstallCommand() {
    if (this.installCommand) {
      this.commandCopied = false;
      navigator.clipboard.writeText(this.installCommand).then(
        () => {
          this.commandCopied = true;
          this.externalActionMessage = 'Install command copied.';
          this.externalError = '';
          this.cdr.detectChanges();
          setTimeout(() => {
            this.commandCopied = false;
            this.cdr.detectChanges();
          }, 2500);
        },
        () => {
          this.externalError = 'Failed to copy to clipboard.';
          this.cdr.detectChanges();
        }
      );
    }
  }

  isSensorRunning(sensor: ExternalSensorCard): boolean {
    return sensor['agent-z'] === 'running' || sensor['agent-s'] === 'running' || sensor.vector === 'running';
  }

  isCommandPending(sensor: ExternalSensorCard, command?: SensorControlCommand): boolean {
    if (!this.pendingExternalCommand) {
      return false;
    }

    return this.pendingExternalCommand.sensorId === sensor.key_prefix
      && (!command || this.pendingExternalCommand.command === command);
  }

  getServiceLabel(status: ExternalServiceStatus): string {
    switch (status) {
      case 'running':
        return 'Running';
      case 'stopped':
        return 'Stopped';
      case 'restarting':
        return 'Restarting';
      default:
        return 'Unavailable';
    }
  }

  formatRelativeTime(value: string): string {
    const timestamp = this.parseDate(value);
    if (!timestamp) {
      return 'Never';
    }

    const diffMs = Date.now() - timestamp.getTime();
    const diffSeconds = Math.max(0, Math.floor(diffMs / 1000));

    if (diffSeconds < 45) return 'Just now';

    const diffMinutes = Math.floor(diffSeconds / 60);
    if (diffMinutes < 60) {
      return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
    }

    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) {
      return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
    }

    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  }

  trackSensor(_index: number, sensor: ExternalSensorCard): string {
    return sensor.id;
  }

  private pollStatus(expected: string, attempts = 0) {
    setTimeout(() => {
      this.api.getAgentStatus().subscribe({
        next: (data: any) => {
          if (data) {
            const allRunning =
              this.normalizeStatus(data['agent-z']) === 'running' &&
              this.normalizeStatus(data['agent-s']) === 'running' &&
              this.normalizeStatus(data.vector) === 'running' &&
              (data.arkime == null || this.normalizeStatus(data.arkime) === 'running');
            const noneRunning =
              this.normalizeStatus(data['agent-z']) !== 'running' &&
              this.normalizeStatus(data['agent-s']) !== 'running' &&
              this.normalizeStatus(data.vector) !== 'running';

            const matched =
              (expected === 'Running' && allRunning) ||
              (expected === 'Stopped' && noneRunning);

            if (matched || attempts >= 5) {
              this.status.set('Ready');
              this.updateStatus(data);
              this.cdr.detectChanges();
            } else {
              this.pollStatus(expected, attempts + 1);
            }
          }
        },
        error: () => {
          if (attempts < 5) {
            this.pollStatus(expected, attempts + 1);
          } else {
            this.status.set('Stopped');
            this.cdr.detectChanges();
          }
        },
      });
    }, 2000);
  }

  private normalizeStatus(status: unknown): string {
    const value = String(status || 'stopped').toLowerCase().trim();
    if (['running', 'healthy', 'ok', 'up', 'active', 'started'].includes(value)) return 'running';
    if (['stopped', 'down', 'error', 'failed', 'inactive', 'unknown'].includes(value)) return 'stopped';
    return /^\d+$/.test(value) ? 'running' : value;
  }

  private loadLocalSensorSetup() {
    this.api.getInterfaces().subscribe({
      next: data => {
        this.interfaces = data || [];
        this.cdr.detectChanges();
      },
      error: error => {
        this.showError('Interfaces Load Failed', error?.error?.message || 'Could not load network interfaces.');
      }
    });

    this.api.getAgentStatus().subscribe({
      next: data => {
        if (data) {
          this.updateStatus(data);
          this.cdr.detectChanges();
        }
      },
      error: error => {
        this.showError('Sensor Status Load Failed', error?.error?.message || 'Could not retrieve local sensor service statuses.');
      }
    });

    this.subs.push(
      this.ws.lastAgentStatus$.pipe(
        filter(data => data !== null)
      ).subscribe(data => {
        this.updateStatus(data);
        this.cdr.detectChanges();
      })
    );
  }

  loadExternalSensors(silent = false) {
    if (!this.canViewExternalSensors) {
      return;
    }

    if (!silent) {
      this.externalLoading = true;
    }
    this.externalError = '';

    this.api.getSensorKeys().subscribe({
      next: sensors => {
        this.externalSensors = this.getVisibleExternalSensors(sensors)
          .map(sensor => this.mapExternalSensor(sensor));
        this.externalLoading = false;
        this.cdr.detectChanges();
      },
      error: error => {
        this.externalError = error?.error?.message || 'Unable to load external sensors.';
        this.externalLoading = false;
        this.cdr.detectChanges();
      },
    });
  }

  private getVisibleExternalSensors(sensors: SensorKey[]): SensorKey[] {
    const filtered = sensors.filter(sensor => sensor.key_prefix !== 'local-central');
    if (this.currentRole !== 'tenant_admin') {
      return filtered;
    }
    return filtered.filter(sensor => sensor.active);
  }

  private mapExternalSensor(sensor: SensorKey): ExternalSensorCard {
    const displayName = this.cleanLabel(sensor.name)
      || this.cleanLabel(sensor.hostname)
      || sensor.key_prefix;

    const online = sensor.active && this.isRecentlySeen(sensor.last_seen);
    const neverRegistered = !sensor.hostname || sensor.hostname.trim() === '';

    return {
      ...sensor,
      displayName,
      hostname: this.cleanLabel(sensor.hostname) || 'Unregistered host',
      interface: sensor.interface || 'Unavailable',
      os: sensor.os || 'Unavailable',
      'agent-z': online ? this.normalizeExternalStatus(sensor['agent-z']) : (neverRegistered ? 'unknown' : 'stopped'),
      'agent-s': online ? this.normalizeExternalStatus(sensor['agent-s']) : (neverRegistered ? 'unknown' : 'stopped'),
      vector:    online ? this.normalizeExternalStatus(sensor.vector)      : (neverRegistered ? 'unknown' : 'stopped'),
      online,
    };
  }

  private isRecentlySeen(value: string): boolean {
    const timestamp = this.parseDate(value);
    if (!timestamp) {
      return false;
    }

    // 5 min: the engine records last_seen about every 2 min for a healthy sensor (it does not
    // write on every 30 s check-in), so a 2 min window showed running sensors as offline.
    return Date.now() - timestamp.getTime() <= 300000;
  }

  private parseDate(value: string): Date | null {
    if (!value) {
      return null;
    }

    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const parsed = new Date(withTimezone);

    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }

    const fallback = new Date(value);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }

  private normalizeExternalStatus(status: unknown): ExternalServiceStatus {
    const value = String(status || 'unknown').toLowerCase().trim();
    if (value === 'running') return 'running';
    if (value === 'stopped') return 'stopped';
    if (value === 'restarting') return 'restarting';
    return 'unknown';
  }

  private getSensorDisplayName(sensor: ExternalSensorCard): string {
    return this.cleanLabel(sensor.displayName) || this.cleanLabel(sensor.name) || sensor.key_prefix;
  }

  private cleanLabel(value: unknown): string {
    return String(value || '').trim();
  }

  private getCommandLabel(command: SensorControlCommand): string {
    switch (command) {
      case 'start':
        return 'Start command';
      case 'stop':
        return 'Stop command';
      case 'restart':
        return 'Restart command';
    }
  }

  private buildInstallCommand(key: string): string {
    const url = this.customServerUrl.trim() || this.cloudUrl;
    return `curl -fsSL ${url}/api/install-sensor.sh | sudo bash -s -- --cloud-url ${url} --tenant-id ${this.currentTenantId} --api-key ${key}`;
  }

  rebuildInstallCommand() {
    if (this.createdSensorKey?.key) {
      this.installCommand = this.buildInstallCommand(this.createdSensorKey.key);
      this.cdr.detectChanges();
    }
  }

  private detectCloudUrl(): string {
    if (typeof window === 'undefined') {
      return 'https://your-ndr.com';
    }

    const url = new URL(window.location.origin);
    if (url.port === '4200') {
      url.port = '3000';
    }
    return url.origin;
  }

  private copyText(value: string, successMessage: string) {
    navigator.clipboard.writeText(value).then(
      () => {
        this.externalActionMessage = successMessage;
        this.externalError = '';
        this.cdr.detectChanges();
      },
      () => {
        this.externalError = 'Failed to copy to clipboard.';
        this.cdr.detectChanges();
      }
    );
  }
}
