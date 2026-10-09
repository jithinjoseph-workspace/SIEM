import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { LucideAngularModule, Plus, Radio, Trash2, RefreshCw, CheckCircle, XCircle, AlertTriangle } from 'lucide-angular';

interface SiemSource {
  source_id:   string;
  name:        string;
  source_type: string;
  status:      string;
  last_seen_at: string;
  eps:          number;
  config_json:  any;
}

interface NewSource {
  name:        string;
  source_type: string;
  config:      string;
}

@Component({
  selector: 'app-siem-sources',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-sources.html',
  styleUrl: './siem-sources.css',
})
export class SiemSources implements OnInit {

  sources    = signal<SiemSource[]>([]);
  loading    = signal(true);
  error      = signal<string | null>(null);
  showModal  = signal(false);
  saving     = signal(false);
  newKeyData   = signal<{ source_id: string; ingest_key: string; source_type: string; name: string } | null>(null);
  keyCopied    = signal(false);
  cmdCopied    = signal(false);

  newSource: NewSource = { name: '', source_type: 'syslog', config: '' };

  readonly sourceTypes = [
    { value: 'wec',           label: 'WEC (Windows Events)',  hint: 'HTTPS :5044' },
    { value: 'syslog',        label: 'Syslog',                hint: 'TCP/UDP :514/:601/:6514' },
    { value: 'firewall_cef',  label: 'Firewall CEF',          hint: 'Syslog CEF format' },
    { value: 'generic',       label: 'Generic REST',          hint: 'POST /api/siem/ingest' },
    { value: 'aws_cloudtrail',label: 'AWS CloudTrail',        hint: 'REST pull from S3/SQS' },
  ];

  readonly PlusIcon    = Plus;
  readonly RadioIcon   = Radio;
  readonly DeleteIcon  = Trash2;
  readonly RefreshIcon = RefreshCw;
  readonly OkIcon      = CheckCircle;
  readonly ErrIcon     = XCircle;
  readonly WarnIcon    = AlertTriangle;

  constructor(private http: HttpClient) {}

  ngOnInit() { this.load(); }

  load() {
    this.loading.set(true);
    this.http.get<{ sources: SiemSource[] }>('/api/siem/sources').subscribe({
      next: res => { this.sources.set(res.sources ?? []); this.loading.set(false); },
      error: () => { this.error.set('Failed to load sources'); this.loading.set(false); }
    });
  }

  openModal() {
    this.newSource = { name: '', source_type: 'syslog', config: '' };
    this.showModal.set(true);
  }

  closeModal() { this.showModal.set(false); }

  addSource() {
    if (!this.newSource.name.trim()) return;
    this.saving.set(true);
    this.http.post<{ source_id: string; ingest_key: string }>('/api/siem/sources', {
      name:        this.newSource.name.trim(),
      source_type: this.newSource.source_type,
      config_json: this.newSource.config || '{}',
    }).subscribe({
      next: (res) => {
        this.saving.set(false);
        this.closeModal();
        this.load();
        // Show key reveal dialog — key is only returned once
        this.newKeyData.set({ source_id: res.source_id, ingest_key: res.ingest_key,
                               source_type: this.newSource.source_type, name: this.newSource.name.trim() });
        this.keyCopied.set(false);
        this.cmdCopied.set(false);
      },
      error: () => { this.saving.set(false); this.error.set('Failed to add source'); }
    });
  }

  copyKey() {
    const key = this.newKeyData()?.ingest_key;
    if (!key) return;
    navigator.clipboard.writeText(key).then(() => {
      this.keyCopied.set(true);
      setTimeout(() => this.keyCopied.set(false), 3000);
    });
  }

  copyCmd() {
    const d = this.newKeyData();
    if (!d) return;
    navigator.clipboard.writeText(this.setupCommand(d.source_type, d.ingest_key)).then(() => {
      this.cmdCopied.set(true);
      setTimeout(() => this.cmdCopied.set(false), 3000);
    });
  }

  dismissKey() { this.newKeyData.set(null); }

  setupCommand(sourceType: string, key: string): string {
    const host = window.location.hostname;
    switch (sourceType) {
      case 'wec':
        return `# ── Step 1: Enable WinRM on all endpoints via GPO (no agent needed) ──────
# Group Policy: Computer Config → Windows Settings → Scripts → Startup
#   winrm quickconfig -force

# ── Step 2: On the WEC collector server — create forwarding subscription ──
# wecutil cs C:\\subscription.xml
# (subscription.xml points endpoints to this collector via GPO)

# ── Step 3: Install Winlogbeat ONLY on the WEC collector server ───────────
# winlogbeat.yml — reads ALL forwarded events from every endpoint
winlogbeat.event_logs:
  - name: ForwardedEvents      # collects from all GPO-enrolled machines
  - name: Security
  - name: System
  - name: Application

output.elasticsearch:
  hosts: ["http://${host}:3002"]
  api_key: "${key}"

# Result: zero agents on endpoints — only one Winlogbeat on the WEC server`;

      case 'syslog':
      case 'firewall_cef':
        return `# /etc/rsyslog.d/99-promasecure-siem.conf
*.* action(type="omfwd"
    target="${host}" port="514" protocol="udp"
    Template="RSYSLOG_FileFormat")

# For TLS (recommended):
# *.* action(type="omfwd" target="${host}" port="6514" protocol="tcp"
#     StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon")`;

      case 'generic':
      default:
        return `# Option A — REST ingest (any HTTP client)
curl -X POST http://${host}:3002/api/siem/ingest \\
  -H "Authorization: Bearer ${key}" \\
  -H "Content-Type: application/json" \\
  -d '{"raw_log":"<your log line>","source_type":"rest"}'

# Option B — Winlogbeat / Filebeat (output.elasticsearch)
output.elasticsearch:
  hosts: ["http://${host}:3002"]
  api_key: "${key}"`;

      case 'aws_cloudtrail':
        return `# AWS CloudTrail — configure S3 export + SQS notification
# PromaSecure pulls from SQS queue automatically once configured.
# Set SQS queue URL in Config JSON:
# {"sqs_url":"https://sqs.<region>.amazonaws.com/<account>/<queue>",
#  "region":"us-east-1"}
# API key: ${key}`;
    }
  }

  setupLabel(sourceType: string): string {
    const labels: Record<string, string> = {
      wec:            'WEF setup (no agent on endpoints)',
      syslog:         'rsyslog config',
      firewall_cef:   'rsyslog CEF config',
      generic:        'curl command',
      aws_cloudtrail: 'AWS setup',
    };
    return labels[sourceType] ?? 'setup command';
  }

  deleteSource(id: string) {
    if (!confirm('Delete this source?')) return;
    this.http.delete(`/api/siem/sources/${id}`).subscribe({ next: () => this.load(), error: () => {} });
  }

  statusIcon(s: string) {
    return s === 'active' ? this.OkIcon : s === 'error' ? this.ErrIcon : this.WarnIcon;
  }

  statusClass(s: string): string {
    return ({ active: 'status-ok', error: 'status-err', paused: 'status-warn' } as any)[s] ?? 'status-warn';
  }

  sourceTypeLabel(t: string): string {
    return this.sourceTypes.find(x => x.value === t)?.label ?? t;
  }

  sourceTypeHint(t: string): string {
    return this.sourceTypes.find(x => x.value === t)?.hint ?? '';
  }

  get selectedTypeHint(): string { return this.sourceTypeHint(this.newSource.source_type); }
}
