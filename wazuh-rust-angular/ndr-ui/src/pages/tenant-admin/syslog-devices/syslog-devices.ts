import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { LucideAngularModule, Plus, ShieldCheck, Trash2, RefreshCw, Download, Network } from 'lucide-angular';

interface SyslogDevice {
  id: string;
  tenant_id: string;
  name: string;
  fingerprint: string;
  created_at: string;
  last_seen: string | null;
}

interface SyslogSource {
  ip: string;
  tenant_id: string;
  label: string;
  created_at: string;
}

interface DeviceBundle {
  device: SyslogDevice;
  ca_crt: string;
  client_crt: string;
  client_key: string;
  port: number;
}

/** Per-tenant syslog: TLS devices (client certificates, :6514) and plain-syslog source IPs. */
@Component({
  selector: 'app-syslog-devices',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './syslog-devices.html',
  styleUrl: '../../siem/sources/siem-sources.css',
})
export class SyslogDevices implements OnInit {
  devices = signal<SyslogDevice[]>([]);
  sources = signal<SyslogSource[]>([]);
  loading = signal(true);
  error = signal<string | null>(null);
  saving = signal(false);
  showDevice = signal(false);
  showSource = signal(false);
  /** The certificate bundle of a new device: its key is shown once. */
  bundle = signal<DeviceBundle | null>(null);

  deviceName = '';
  sourceIp = '';
  sourceLabel = '';
  readonly host = window.location.hostname;

  readonly PlusIcon = Plus;
  readonly TlsIcon = ShieldCheck;
  readonly DeleteIcon = Trash2;
  readonly RefreshIcon = RefreshCw;
  readonly DownloadIcon = Download;
  readonly NetIcon = Network;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.error.set(null);
    this.http.get<{ devices: SyslogDevice[] }>('/api/v1/syslog/devices').subscribe({
      next: (r) => {
        this.devices.set(r.devices ?? []);
        this.loading.set(false);
      },
      error: (e) => {
        this.error.set(e.status === 403 ? 'Only tenant administrators can manage syslog devices.' : 'Failed to load syslog devices');
        this.loading.set(false);
      },
    });
    this.http.get<{ sources: SyslogSource[] }>('/api/v1/syslog/sources').subscribe({
      next: (r) => this.sources.set(r.sources ?? []),
      error: () => {},
    });
  }

  addDevice() {
    const name = this.deviceName.trim();
    if (!name) return;
    this.saving.set(true);
    this.http.post<DeviceBundle>('/api/v1/syslog/devices', { name }).subscribe({
      next: (b) => {
        this.saving.set(false);
        this.showDevice.set(false);
        this.deviceName = '';
        this.bundle.set(b);
        this.load();
      },
      error: (e) => {
        this.saving.set(false);
        this.error.set(e.error?.message ?? 'Failed to issue the certificate');
      },
    });
  }

  revoke(d: SyslogDevice) {
    if (!confirm(`Revoke "${d.name}"? It can no longer send logs.`)) return;
    this.http.delete(`/api/v1/syslog/devices/${d.id}`).subscribe({
      next: () => this.load(),
      error: () => this.error.set('Failed to revoke the device'),
    });
  }

  addSource() {
    const ip = this.sourceIp.trim();
    if (!ip) return;
    this.saving.set(true);
    this.http.post('/api/v1/syslog/sources', { ip, label: this.sourceLabel.trim() }).subscribe({
      next: () => {
        this.saving.set(false);
        this.showSource.set(false);
        this.sourceIp = '';
        this.sourceLabel = '';
        this.load();
      },
      error: (e) => {
        this.saving.set(false);
        this.error.set(e.error?.message ?? 'Failed to add the address');
      },
    });
  }

  removeSource(s: SyslogSource) {
    if (!confirm(`Remove ${s.ip}? Its logs go to the default tenant afterwards.`)) return;
    this.http.delete(`/api/v1/syslog/sources/${encodeURIComponent(s.ip)}`).subscribe({
      next: () => this.load(),
      error: () => this.error.set('Failed to remove the address'),
    });
  }

  download(file: string, text: string) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = file;
    a.click();
    URL.revokeObjectURL(url);
  }

  downloadAll(b: DeviceBundle) {
    const n = b.device.name.replace(/[^A-Za-z0-9._-]/g, '_');
    this.download('ca.crt', b.ca_crt);
    this.download(`${n}.crt`, b.client_crt);
    this.download(`${n}.key`, b.client_key);
  }

  rsyslogExample(b: DeviceBundle): string {
    const n = b.device.name.replace(/[^A-Za-z0-9._-]/g, '_');
    return `# /etc/rsyslog.d/90-provigil.conf  (needs: rsyslog-gnutls or rsyslog-openssl)
global(DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.crt"
       DefaultNetstreamDriverCertFile="/etc/rsyslog.d/${n}.crt"
       DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/${n}.key")
*.* action(type="omfwd" target="${this.host}" port="${b.port}" protocol="tcp"
           StreamDriver="gtls" StreamDriverMode="1"
           StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="${this.host}")`;
  }

  copy(text: string) {
    navigator.clipboard.writeText(text);
  }

  short(fp: string) {
    return fp.slice(0, 16) + '…';
  }
}
