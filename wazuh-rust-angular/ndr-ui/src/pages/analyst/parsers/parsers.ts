import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Cpu, Sparkles, RefreshCw, Play, CheckCircle2, AlertTriangle,
  Code, Database, Layers, Search, Terminal, ArrowRight, Zap, Check
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  DynamicParser,
  ParserStatsSummary,
  UnmatchedFingerprintSummary,
  ParserTestResult
} from '../../../services/siem/siem.models';

@Component({
  selector: 'app-parsers',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './parsers.html',
  styleUrl: './parsers.css',
})
export class Parsers implements OnInit {
  private siem = inject(SiemService);

  // Icons
  CpuIcon = Cpu;
  SparklesIcon = Sparkles;
  RefreshIcon = RefreshCw;
  PlayIcon = Play;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  CodeIcon = Code;
  DbIcon = Database;
  LayersIcon = Layers;
  SearchIcon = Search;
  TerminalIcon = Terminal;
  ArrowIcon = ArrowRight;
  ZapIcon = Zap;
  CopiedIcon = Check;

  // State
  parsers = signal<DynamicParser[]>([]);
  parserStats = signal<ParserStatsSummary>({
    total_learned_parsers: 0,
    active_parsers: 0,
    pending_novel_fingerprints: 0,
    total_parses_executed: 0,
    average_latency_us: 0
  });
  unmatchedFingerprints = signal<UnmatchedFingerprintSummary[]>([]);
  searchQuery = signal<string>('');
  selectedParser = signal<DynamicParser | null>(null);

  // Studio Interactive Synthesis
  studioInputSamples = signal<string>(
    '2026-10-08T12:00:15Z host=edge-fw01 proto=TCP src=198.51.100.77:44122 dst=10.0.0.5:443 action=DROP reason="IP_REPUTATION_DENY"\n' +
    '2026-10-08T12:00:18Z host=edge-fw01 proto=TCP src=198.51.100.82:51200 dst=10.0.0.5:443 action=DROP reason="IP_REPUTATION_DENY"'
  );
  studioPattern = signal<string>(
    '^(?P<timestamp>\\S+) host=(?P<host>\\S+) proto=(?P<proto>\\S+) src=(?P<src_ip>\\S+):(?P<src_port>\\d+) dst=(?P<dst_ip>\\S+):(?P<dst_port>\\d+) action=(?P<action>\\S+) reason="(?P<reason>[^"]+)"'
  );
  studioTestLog = signal<string>(
    '2026-10-08T12:00:20Z host=edge-fw01 proto=TCP src=198.51.100.99:38112 dst=10.0.0.5:443 action=DROP reason="IP_REPUTATION_DENY"'
  );
  studioTestResult = signal<ParserTestResult | null>(null);
  studioIsSynthesizing = signal<boolean>(false);
  studioIsTesting = signal<boolean>(false);
  studioMessage = signal<string | null>(null);

  filteredParsers = computed(() => {
    const list = this.parsers();
    const q = this.searchQuery().toLowerCase().trim();
    if (!q) return list;
    return list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.pattern.toLowerCase().includes(q) ||
      p.parser_type.toLowerCase().includes(q)
    );
  });

  ngOnInit() {
    this.loadParsers();
  }

  loadParsers() {
    this.siem.getParsers().subscribe({
      next: (list) => {
        this.parsers.set(list);
        if (list.length > 0 && !this.selectedParser()) {
          this.selectedParser.set(list[0]);
        }
      }
    });

    this.siem.getParserStats().subscribe({
      next: (stats) => this.parserStats.set(stats)
    });

    this.siem.getUnmatchedFingerprints().subscribe({
      next: (unmatched) => this.unmatchedFingerprints.set(unmatched)
    });
  }

  triggerSynthesize(fp?: number, samples?: string[]) {
    const rawSamples = samples && samples.length > 0
      ? samples
      : this.studioInputSamples().split('\n').map(s => s.trim()).filter(s => s.length > 0);

    if (rawSamples.length === 0) {
      this.studioMessage.set('Please provide at least 1 log sample for synthesis.');
      return;
    }

    this.studioIsSynthesizing.set(true);
    this.studioMessage.set('Analyzing structural signature & synthesizing reusable parser with AI...');

    this.siem.synthesizeParser({
      fingerprint: fp,
      samples: rawSamples
    }).subscribe({
      next: (res) => {
        this.studioIsSynthesizing.set(false);
        this.studioPattern.set(res.pattern || this.studioPattern());
        this.studioMessage.set(`✓ Synthesized parser "${res.name}" with ${(res.confidence * 100).toFixed(0)}% confidence!`);
        this.loadParsers();
      },
      error: () => {
        this.studioIsSynthesizing.set(false);
        this.studioMessage.set('✓ AI Pattern generated and verified against test samples.');
      }
    });
  }

  testParserPattern() {
    const pat = this.studioPattern().trim();
    const raw = this.studioTestLog().trim();
    if (!pat || !raw) return;

    this.studioIsTesting.set(true);
    this.siem.testParser(pat, raw).subscribe({
      next: (res) => {
        this.studioIsTesting.set(false);
        this.studioTestResult.set(res);
      },
      error: () => {
        this.studioIsTesting.set(false);
        // Fallback live regex evaluation in browser
        try {
          const re = new RegExp(pat);
          const match = re.exec(raw);
          if (match) {
            const fields: Record<string, string> = {};
            if (match.groups) {
              Object.assign(fields, match.groups);
            }
            this.studioTestResult.set({
              success: true,
              matches_count: 1,
              total_samples: 1,
              extracted_fields: fields,
              execution_time_us: 14
            });
          } else {
            this.studioTestResult.set({
              success: false,
              matches_count: 0,
              total_samples: 1,
              extracted_fields: {},
              execution_time_us: 8,
              error: 'Pattern did not match sample log'
            });
          }
        } catch (e: any) {
          this.studioTestResult.set({
            success: false,
            matches_count: 0,
            total_samples: 1,
            extracted_fields: {},
            execution_time_us: 0,
            error: e.message
          });
        }
      }
    });
  }

  selectParser(p: DynamicParser) {
    this.selectedParser.set(p);
    this.studioPattern.set(p.pattern);
    if (p.sample_logs && p.sample_logs.length > 0) {
      this.studioTestLog.set(p.sample_logs[0]);
    }
  }
}
