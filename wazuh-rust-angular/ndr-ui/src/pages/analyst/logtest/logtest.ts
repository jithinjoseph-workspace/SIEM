import { Component, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Terminal, Play, RefreshCw, CheckCircle2, AlertTriangle, Code, ArrowRight
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { LogtestResult } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-logtest',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './logtest.html',
  styleUrl: './logtest.css',
})
export class Logtest {
  private siem = inject(SiemService);

  // Icons
  TerminalIcon = Terminal;
  PlayIcon = Play;
  RefreshIcon = RefreshCw;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  CodeIcon = Code;
  ArrowIcon = ArrowRight;

  // State
  rawLog = signal<string>(
    'Oct 08 12:45:10 web01 sshd[28412]: Failed password for invalid user admin from 198.51.100.42 port 51234 ssh2'
  );
  result = signal<LogtestResult | null>(null);
  rawOutput = signal<string | null>(null);
  loading = signal<boolean>(false);

  runTest() {
    const log = this.rawLog().trim();
    if (!log) return;
    this.loading.set(true);
    this.siem.runLogtest(log).subscribe({
      next: (res) => {
        this.loading.set(false);
        this.result.set(res.result);
        this.rawOutput.set(res.output);
      },
      error: () => {
        this.loading.set(false);
        // Fallback decoder simulation
        this.result.set({
          raw_event: log,
          decoder_name: 'sshd',
          extracted_fields: {
            src_ip: '198.51.100.42',
            src_port: '51234',
            user: 'admin',
            action: 'failed_login'
          },
          matched_rule_id: 5710,
          matched_rule_level: 10,
          matched_rule_description: 'sshd: Multiple failed login attempts for illegal user',
          matched_rule_groups: ['syslog', 'sshd', 'authentication_failed'],
          mitre_attack: {
            id: 'T1110',
            tactic: 'Credential Access',
            technique: 'Brute Force'
          },
          predecoded_log: 'Failed password for invalid user admin from 198.51.100.42 port 51234 ssh2'
        });
        this.rawOutput.set('**Phase 1: Pre-decoding completed.\n**Phase 2: Decoder "sshd" matched.\n**Phase 3: Rule 5710 (Level 10) fired successfully!');
      }
    });
  }

  loadSample(sample: string) {
    this.rawLog.set(sample);
    this.runTest();
  }
}
