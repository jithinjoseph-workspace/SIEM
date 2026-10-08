import { ChangeDetectorRef, Directive } from '@angular/core';
import { Gavel, Plus, Edit, Trash2, Power, RefreshCcw, X, Info, Download } from 'lucide-angular';
import { Api } from '../../../services/api/api';

/**
 * Shared rule-form CRUD + reference data for the admin and analyst rules
 * pages. The two pages load/list/filter/paginate rules very differently
 * (admin fetches everything and paginates client-side; analyst fetches
 * server-paginated Agent-Z rules and merges in a separate Agent-S fired-rule
 * source with its own tabs/category filters) — that part stays page-specific
 * on purpose. What was genuinely duplicated (byte-for-byte identical logic,
 * just renamed here and there) is the add/edit/save/delete/toggle form flow
 * and the field/matcher/severity reference lists, so only that lives here.
 */
@Directive()
export abstract class RulesBase {
  loading       = true;
  saving        = false;
  syncing       = false;
  showForm      = false;
  isEditing     = false;
  editingId     = '';
  totalHits     = 0;
  message       = '';
  messageType   = '';
  showConnHelp  = false;
  showFieldInfo = false;

  /** Rules displayed by the concrete page — deleteRule/toggleRule mutate this. */
  abstract rules: any[];

  ruleForm = {
    title: '', severity: 'medium', description: '',
    field: 'event_type', value: '', matcher: 'equals', tags: [] as string[],
  };

  fieldOptions = [
    { value: 'event_type',       label: 'Event Type',           description: 'Type of event from Agent-S',              examples: ['alert', 'flow', 'dns', 'http', 'tls', 'quic'] },
    { value: 'proto',            label: 'Protocol',             description: 'Network protocol (lowercase)',            examples: ['tcp', 'udp', 'icmp', 'ipv6-icmp'] },
    { value: 'source_ip',        label: 'Source IP',            description: 'IP address of the sender',                examples: ['10.0.2.15', '192.168.1.1'] },
    { value: 'dest_ip',          label: 'Destination IP',       description: 'IP address of the receiver',              examples: ['93.184.216.34', '8.8.8.8'] },
    { value: 'conn_state',       label: 'Connection State',     description: 'Agent-Z connection state code',           examples: ['S0', 'REJ', 'SF', 'OTH', 'RSTO'] },
    { value: 'network_protocol', label: 'Application Protocol', description: 'Layer 7 protocol detected by Agent-Z',    examples: ['dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp'] },
    { value: 'alert.severity',   label: 'Alert Severity',       description: 'Agent-S severity (1=high, 2=med, 3=low)', examples: ['1', '2', '3'] },
    { value: 'alert.signature',  label: 'Alert Signature',      description: 'Agent-S rule signature name',             examples: ['ET MALWARE', 'ET SCAN', 'ET POLICY'] },
    { value: 'alert.category',   label: 'Alert Category',       description: 'Agent-S alert category',                  examples: ['Malware', 'Exploit', 'Policy Violation'] },
    { value: 'log_source',       label: 'Log Source (Agent-Z)', description: 'Agent-Z log type',                        examples: ['conn', 'dns', 'http', 'ssl', 'ssh'] },
    { value: 'Image',            label: 'Process Image',        description: 'Full path of the executed binary',        examples: ['/bin/bash', '/usr/bin/curl', '/tmp/malware', '/bin/sh'] },
    { value: 'CommandLine',      label: 'Command Line',         description: 'Full command including arguments',        examples: ['curl http://', 'chmod +x', 'wget ', 'nc -e /bin/sh'] },
    { value: 'ParentImage',      label: 'Parent Process',       description: 'Path of the parent process that spawned this one', examples: ['/bin/bash', '/usr/sbin/sshd', '/bin/sh'] },
    { value: 'TargetFilename',   label: 'Target Filename',      description: 'File path written or modified',           examples: ['/etc/crontab', '/root/.ssh/', '/tmp/', '/etc/passwd'] },
    { value: 'DestinationIp',    label: 'Destination IP (Endpoint)',   description: 'Outbound connection destination from a Linux process', examples: ['10.0.0.1', '192.168.', '8.8.8.8'] },
    { value: 'DestinationPort',  label: 'Destination Port (Endpoint)', description: 'Outbound connection port from a Linux process',         examples: ['4444', '1337', '31337', '443'] },
    { value: 'User',             label: 'User',                 description: 'Linux user account running the process',  examples: ['root', 'www-data', 'nobody'] },
    { value: 'type',             label: 'Auditd Record Type',   description: 'Type of auditd event record',             examples: ['EXECVE', 'SYSCALL', 'PATH', 'SOCKADDR'] },
  ];

  connStateHelp = [
    { state: 'S0',   meaning: 'No reply — possible scan' },
    { state: 'REJ',  meaning: 'Connection rejected' },
    { state: 'SF',   meaning: 'Normal connection' },
    { state: 'OTH',  meaning: 'Mid-stream, no SYN' },
    { state: 'RSTO', meaning: 'Originator sent RST' },
    { state: 'RSTR', meaning: 'Responder sent RST' },
  ];

  matcherOptions = [
    { value: 'equals',     label: 'Equals',      description: 'Exact match' },
    { value: 'contains',   label: 'Contains',    description: 'Partial match' },
    { value: 'startswith', label: 'Starts With', description: 'Prefix match' },
    { value: 'endswith',   label: 'Ends With',   description: 'Suffix match' },
    { value: 're',         label: 'Regex',       description: 'Pattern match' },
  ];

  severityOptions = [
    { value: 'critical', label: 'Critical', color: 'text-red-400',    description: 'Immediate action required' },
    { value: 'high',     label: 'High',     color: 'text-orange-400', description: 'Serious threat' },
    { value: 'medium',   label: 'Medium',   color: 'text-yellow-400', description: 'Suspicious activity' },
    { value: 'low',      label: 'Low',      color: 'text-blue-400',   description: 'Informational' },
  ];

  GavelIcon    = Gavel;
  PlusIcon     = Plus;
  EditIcon     = Edit;
  TrashIcon    = Trash2;
  PowerIcon    = Power;
  RefreshIcon  = RefreshCcw;
  XIcon        = X;
  InfoIcon     = Info;
  DownloadIcon = Download;

  constructor(protected api: Api, protected cdr: ChangeDetectorRef) {}

  get selectedField() {
    return this.fieldOptions.find(f => f.value === this.ruleForm.field);
  }

  get selectedSeverity() {
    return this.severityOptions.find(s => s.value === this.ruleForm.severity);
  }

  getPlaceholder(): string {
    return this.selectedField?.examples?.[0] || 'Enter value';
  }

  /** Re-fetches whatever this page's rule list(s) are — implemented per page. */
  abstract loadRules(): void;

  syncCommunityRules(): void {
    this.syncing = true;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncing = false;
        if (res.status === 'already_running') {
          this.showMessage(res.message || 'Sync already in progress — check back in a minute', 'success');
        } else {
          this.showMessage('Sync started in background — refresh rules in a minute', 'success');
          setTimeout(() => this.loadRules(), 60_000);
        }
      },
      error: (err: any) => {
        this.syncing = false;
        this.showMessage(err?.error?.error || err?.error?.message || 'Sync failed — check engine connectivity', 'error');
      },
    });
  }

  openAddForm(): void {
    this.isEditing = false;
    this.editingId = '';
    this.resetForm();
    this.showForm = true;
  }

  openEditForm(rule: any): void {
    this.isEditing = true;
    this.editingId = rule.id;
    this.showForm = true;

    this.api.getRuleById(rule.id).subscribe({
      next: (data: any) => {
        this.ruleForm = {
          title: data.title || rule.name,
          severity: data.severity || 'medium',
          description: data.description || '',
          field: data.field || 'event_type',
          value: data.value || '',
          matcher: data.matcher || 'equals',
          tags: data.tags || [],
        };
        this.cdr.detectChanges();
      },
      error: () => {
        this.ruleForm = {
          title: rule.name,
          severity: rule.severity.toLowerCase(),
          description: rule.description || '',
          field: 'event_type',
          value: '',
          matcher: 'equals',
          tags: rule.tags || [],
        };
        this.cdr.detectChanges();
      },
    });
  }

  saveRule(): void {
    if (!this.ruleForm.title || !this.ruleForm.value) {
      this.showMessage('Title and Value are required', 'error');
      return;
    }
    this.saving = true;

    if (this.isEditing) {
      this.api.deleteRule(this.editingId).subscribe({
        next: () => this.createNewRule(),
        error: () => this.createNewRule(),
      });
    } else {
      this.createNewRule();
    }
  }

  createNewRule(): void {
    this.api.createRule(this.ruleForm).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'created') {
          this.api.reloadRules().subscribe({
            next: (reload: any) => {
              const action = this.isEditing ? 'updated' : 'created';
              this.showMessage(`Rule "${this.ruleForm.title}" ${action}. ${reload.count} rules active.`, 'success');
              this.showForm = false;
              this.resetForm();
              this.loadRules();
              this.cdr.detectChanges();
            },
            error: () => {
              this.showMessage('Rule saved, but reload failed — restart the engine to apply it', 'error');
              this.cdr.detectChanges();
            },
          });
        } else {
          this.showMessage(data.message || 'Error', 'error');
          this.saving = false;
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.saving = false;
        this.showMessage('Failed to save rule', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  deleteRule(rule: any): void {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    this.api.deleteRule(rule.id).subscribe({
      next: () => this.api.reloadRules().subscribe({
        next: () => {
          this.rules = this.rules.filter(r => r.id !== rule.id);
          this.showMessage(`Rule "${rule.name}" deleted`, 'success');
          this.cdr.detectChanges();
        },
        error: () => {
          this.showMessage('Rule deleted, but reload failed — restart the engine to apply it', 'error');
          this.cdr.detectChanges();
        },
      }),
      error: () => this.showMessage('Failed to delete rule', 'error'),
    });
  }

  toggleRule(rule: any): void {
    const enable = rule.status !== 'ACTIVE';
    this.api.toggleRule(rule.id, enable).subscribe({
      next: (data: any) => {
        rule.status = enable ? 'ACTIVE' : 'INACTIVE';
        this.showMessage(`Rule "${rule.name}" ${enable ? 'enabled' : 'disabled'} — ${data.active_rules} active`, 'success');
        this.cdr.detectChanges();
      },
      error: () => this.showMessage('Failed to toggle rule', 'error'),
    });
  }

  showMessage(msg: string, type: string): void {
    this.message = msg;
    this.messageType = type;
    setTimeout(() => {
      this.message = '';
      this.cdr.detectChanges();
    }, 6000);
  }

  resetForm(): void {
    this.ruleForm = {
      title: '', severity: 'medium', description: '',
      field: 'event_type', value: '', matcher: 'equals', tags: [],
    };
    this.showConnHelp = false;
    this.showFieldInfo = false;
    this.isEditing = false;
    this.editingId = '';
  }
}
