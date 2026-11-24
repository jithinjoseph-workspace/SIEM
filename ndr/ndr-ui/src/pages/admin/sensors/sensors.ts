import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Copy, KeyRound, RefreshCw, X, Radio, ShieldCheck, Wifi, CheckCircle2, AlertTriangle, Clock, Layers, Zap, Building2, Search, Trash2, Server, Lock, Activity, Terminal
} from 'lucide-angular';
import { Api, SensorKey } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-sensors',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './sensors.html',
  styleUrl: './sensors.css',
})
export class Sensors implements OnInit {
  Math = Math;

  CopyIcon          = Copy;
  KeyIcon           = KeyRound;
  RefreshIcon       = RefreshCw;
  XIcon             = X;
  RadioIcon         = Radio;
  ShieldCheckIcon   = ShieldCheck;
  WifiIcon          = Wifi;
  CheckCircleIcon   = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;
  ClockIcon         = Clock;
  LayersIcon        = Layers;
  ZapIcon           = Zap;
  BuildingIcon      = Building2;
  SearchIcon        = Search;
  TrashIcon         = Trash2;
  ServerIcon        = Server;
  LockIcon          = Lock;
  ActivityIcon      = Activity;
  TerminalIcon      = Terminal;

  tenants: any[]          = [];
  sensorKeys: SensorKey[] = [];
  loadingSensorKeys       = false;
  creatingSensorKey       = false;
  newSensorKey            = { tenant_id: '', name: '' };
  createdSensorKey: SensorKey | null = null;
  showSensorKeyModal      = false;
  installCommand          = '';
  interfaces: string[]    = [];
  sensorSearch            = '';

  msg     = '';
  msgType = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {}

  get activeSensorsCount(): number {
    return this.sensorKeys.filter(s => s.active).length;
  }

  get activeRatioPercent(): number {
    if (!this.sensorKeys.length) return 100;
    return Math.round((this.activeSensorsCount / this.sensorKeys.length) * 100);
  }

  get tenantsCoveredCount(): number {
    return new Set(this.sensorKeys.map(s => s.tenant_id)).size;
  }

  get tenantsCoveredPercent(): number {
    if (!this.tenants.length) return 100;
    return Math.round((this.tenantsCoveredCount / this.tenants.length) * 100);
  }

  get revokedSensorsCount(): number {
    return this.sensorKeys.filter(s => !s.active).length;
  }

  isTenantCovered(tenantId: string): boolean {
    return this.sensorKeys.some(s => s.tenant_id === tenantId && s.active);
  }

  get filteredSensorKeys(): SensorKey[] {
    const q = this.sensorSearch.trim().toLowerCase();
    if (!q) return this.sensorKeys;
    return this.sensorKeys.filter(s =>
      s.name?.toLowerCase().includes(q) ||
      s.key_prefix?.toLowerCase().includes(q) ||
      s.hostname?.toLowerCase().includes(q) ||
      this.tenantName(s.tenant_id).toLowerCase().includes(q)
    );
  }

  ngOnInit() {
    this.loadSensorKeys();
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants = data.tenants || []; this.cdr.detectChanges(); },
      error: reportRxjsError,
    });
    this.api.getInterfaces().subscribe({
      next: (ifaces: any) => {
        if (Array.isArray(ifaces) && ifaces.length > 0) {
          this.interfaces = ifaces;
        } else if (ifaces && Array.isArray(ifaces.interfaces)) {
          this.interfaces = ifaces.interfaces;
        }
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  loadSensorKeys() {
    this.loadingSensorKeys = true;
    this.api.getSensorKeys().subscribe({
      next: (keys: SensorKey[]) => { this.sensorKeys = keys; this.loadingSensorKeys = false; this.cdr.detectChanges(); },
      error: () => { this.loadingSensorKeys = false; this.showMsg('Failed to load sensor keys', 'error'); this.cdr.detectChanges(); },
    });
  }

  createSensorKey() {
    const tenantId = this.newSensorKey.tenant_id;
    const name     = this.newSensorKey.name.trim();
    if (!tenantId || !name) { this.showMsg('Tenant and sensor name are required', 'error'); return; }

    this.creatingSensorKey = true;
    this.api.createSensorKey(tenantId, name).subscribe({
      next: (data: any) => {
        this.creatingSensorKey = false;
        if (data.status === 'ok' && data.key) {
          this.createdSensorKey = {
            id: data.id, key: data.key, key_prefix: data.key.slice(0, 16),
            tenant_id: tenantId, name, active: true, created_at: new Date().toISOString(), last_seen: '',
          };
          this.installCommand = `sudo bash install-sensor.sh --cloud-url https://your-ndr.com --tenant-id ${tenantId} --api-key ${data.key}`;
          this.showSensorKeyModal = true;
          this.newSensorKey = { tenant_id: '', name: '' };
          this.loadSensorKeys();
        } else {
          this.showMsg(data.message || 'Failed to create sensor key', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => { this.creatingSensorKey = false; this.showMsg('Failed to create sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  revokeSensorKey(key: SensorKey) {
    if (!key.active) return;
    this.api.revokeSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') { key.active = false; this.showMsg('Sensor key revoked', 'success'); this.loadSensorKeys(); }
        else { this.showMsg(data.message || 'Failed to revoke sensor key', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to revoke sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  reactivateSensorKey(key: SensorKey) {
    if (key.active) return;
    this.api.reactivateSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') { key.active = true; this.showMsg('Sensor key reactivated', 'success'); this.loadSensorKeys(); }
        else { this.showMsg(data.message || 'Failed to reactivate sensor key', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to reactivate sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  closeSensorKeyModal()    { this.showSensorKeyModal = false; }
  copyCreatedSensorKey()   { if (this.createdSensorKey?.key) this.copyText(this.createdSensorKey.key, 'Sensor key copied'); }
  copyInstallCommand()     { if (this.installCommand) this.copyText(this.installCommand, 'Install command copied'); }

  tenantName(id: string)   { return this.tenants.find(t => t.id === id)?.name || id; }

  private copyText(value: string, successMessage: string) {
    navigator.clipboard.writeText(value).then(
      () => { this.showMsg(successMessage, 'success'); this.cdr.detectChanges(); },
      () => { this.showMsg('Failed to copy to clipboard', 'error'); this.cdr.detectChanges(); }
    );
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
