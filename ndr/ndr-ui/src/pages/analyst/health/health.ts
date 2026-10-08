import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, SensorKey } from '../../../services/api/api';
import { ArkimeService } from '../../../services/arkime/arkime';
import { LucideAngularModule, Cpu, Server, Database, CheckCircle, Activity } from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';

@Component({
  selector: 'app-health',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './health.html',
  styleUrl: './health.css'
})
export class Health implements OnInit, OnDestroy {

  totalEvents: number = 0;
  totalHits: number = 0;
  eventsPerHour: number = 0;
  sessions: number = 0;
  sigmaRules: number = 0;
  activeSensors: number = 0;
  onlineSensors: number = 0;
  lastSensorSeen = '';

  services: any[] = [
    { name: 'Agent-Z IDS',        status: 'unknown', type: 'agent-z',       label: 'Tenant Sensor'     },
    { name: 'Agent-S EVE',    status: 'unknown', type: 'agent-s',   label: 'Tenant Sensor'     },
    { name: 'Telemetry Pipeline', status: 'unknown', type: 'vector',     label: 'Tenant Sensor'     },
    { name: 'PCAP Engine',     status: 'unknown', type: 'arkime',     label: 'Tenant Sensor'     },
    { name: 'Kafka Broker',    status: 'unknown', type: 'kafka',      label: 'Platform Service'  },
    { name: 'NDR Engine',      status: 'unknown', type: 'engine',     label: 'Platform Service'  },
    { name: 'ClickHouse DB',   status: 'unknown', type: 'clickhouse', label: 'Platform Service'  },
  ];

  arkimeUrl = '';

  CpuIcon = Cpu;
  ServerIcon = Server;
  DatabaseIcon = Database;
  CheckIcon = CheckCircle;
  ActivityIcon = Activity;

  private refreshInterval: any;

  constructor(
    private api: Api,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
    private arkime: ArkimeService,
  ) {}

  ngOnInit() {
    this.loadHealth();
    this.refreshInterval = setInterval(() => this.loadHealth(), 10000);
  }

  loadHealth() {
    // Single API call — /api/health returns everything
    this.api.getDashboardStats().subscribe({
      next: (data: any) => {
        this.totalEvents   = data.events_total || 0;
        this.totalHits     = data.hits_total   || 0;
        this.eventsPerHour = data.events_1h    || 0;
        this.sessions      = data.sessions     || 0;
        this.sigmaRules    = data.sigma_rules  || 0;

        // Update all service statuses from services object
        const svc = data.services || {};
        this.updateStatus('kafka', this.normalizeStatus(svc.kafka));
        this.updateStatus('engine', this.normalizeStatus(svc.engine || 'running'));
        this.updateStatus('clickhouse', this.normalizeStatus(svc.clickhouse));
        this.cdr.detectChanges();
      },
      error: () => {
        ['agent-z', 'agent-s', 'vector', 'kafka', 'engine', 'clickhouse']
          .forEach(s => this.updateStatus(s, 'stopped'));
        this.cdr.detectChanges();
      }
    });

    this.loadSensorHealth();
  }


  loadSensorHealth() {
    const user = this.auth.getUser() || {};
    const tenantId = user.tenant_id || 'default';

    this.api.getSensorKeys().subscribe({
      next: (keys: SensorKey[]) => {
        const sensors = keys.filter(sensor =>
          sensor.tenant_id === tenantId && sensor.active !== false
        );

        this.activeSensors = sensors.length;
        this.onlineSensors = sensors.filter(sensor => this.isSensorOnline(sensor)).length;
        this.lastSensorSeen = this.getLatestSeen(sensors);

        this.updateStatus('agent-z', this.rollupServiceStatus(sensors, 'agent-z'));
        this.updateStatus('agent-s', this.rollupServiceStatus(sensors, 'agent-s'));
        this.updateStatus('vector', this.rollupServiceStatus(sensors, 'vector'));
        this.updateStatus('arkime', this.rollupServiceStatus(sensors, 'arkime'));
        
        const arkimeSensors = sensors.filter(s => s.arkime_url);
        if (arkimeSensors.length > 0) {
          this.arkimeUrl = arkimeSensors[0].arkime_url!;
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.activeSensors = 0;
        this.onlineSensors = 0;
        this.lastSensorSeen = err.message || 'API Error';
        ['agent-z', 'agent-s', 'vector', 'arkime'].forEach(service => this.updateStatus(service, 'unknown'));
        this.cdr.detectChanges();
      }
    });
  }

  updateStatus(type: string, status: string) {
    const svc = this.services.find(s => s.type === type);
    if (svc) svc.status = status;
  }

  private normalizeStatus(status: unknown): string {
    const value = String(status || 'unknown').toLowerCase().trim();
    if (!value || value === 'unknown') return 'unknown';
    if (['running', 'healthy', 'ok', 'up', 'active', 'started'].includes(value)) return 'running';
    if (['stopped', 'down', 'error', 'failed', 'inactive'].includes(value)) return 'stopped';
    return /^\d+$/.test(value) ? 'running' : value;
  }

  private isSensorOnline(sensor: SensorKey): boolean {
    if (!sensor.last_seen) return false;
    const ts = sensor.last_seen.includes('T') ? sensor.last_seen : sensor.last_seen.replace(' ', 'T') + 'Z';
    const lastSeenMs = new Date(ts).getTime();
    return !Number.isNaN(lastSeenMs) && Date.now() - lastSeenMs <= 6 * 60 * 1000;
  }

  private rollupServiceStatus(
    sensors: SensorKey[],
    service: 'agent-z' | 'agent-s' | 'vector' | 'arkime'
  ): string {
    const onlineSensors = sensors.filter(sensor => this.isSensorOnline(sensor));
    if (onlineSensors.length === 0) return sensors.length ? 'stopped' : 'unknown';

    const statuses = onlineSensors.map(sensor => this.normalizeStatus(sensor[service]));
    if (statuses.some(status => status === 'running')) return 'running';
    if (statuses.some(status => status === 'unknown')) return 'unknown';
    return 'stopped';
  }

  private getLatestSeen(sensors: SensorKey[]): string {
    const latest = sensors
      .map(sensor => {
        if (!sensor.last_seen) return 0;
        const ts = sensor.last_seen.includes('T') ? sensor.last_seen : sensor.last_seen.replace(' ', 'T') + 'Z';
        return new Date(ts).getTime();
      })
      .filter(value => !Number.isNaN(value))
      .sort((a, b) => b - a)[0];

    return latest ? new Date(latest).toLocaleString() : 'No heartbeat yet';
  }

  getStatusDotClass(status: string): string {
    switch (status) {
      case 'running': return 'bg-primary shadow-[0_0_8px_rgba(105,246,184,0.4)]';
      case 'stopped': return 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]';
      default:        return 'bg-yellow-500 animate-pulse';
    }
  }

  getStatusBadgeClass(status: string): string {
    switch (status) {
      case 'running': return 'text-primary border-primary/20 bg-primary/5';
      case 'stopped': return 'text-red-400 border-red-500/20 bg-red-500/5';
      default:        return 'text-yellow-400 border-yellow-500/20 bg-yellow-500/5';
    }
  }

  getStatusLabel(status: string): string {
    switch (status) {
      case 'running': return 'Healthy';
      case 'stopped': return 'Down';
      default:        return 'Unknown';
    }
  }

  get runningCount(): number {
    return this.services.filter(s => s.status === 'running').length;
  }

  ngOnDestroy() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
  }
}
