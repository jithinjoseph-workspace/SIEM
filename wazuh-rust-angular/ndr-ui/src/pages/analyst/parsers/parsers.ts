import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Cpu, Sparkles, RefreshCw, Play, CheckCircle2, AlertTriangle,
  Code, Database, Layers, Search, Terminal, ArrowRight, Zap, Check, Copy, Trash2, HelpCircle
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
  CopyIcon = Copy;
  CopiedIcon = Check;
  TrashIcon = Trash2;
  HelpIcon = HelpCircle;

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
  copiedPatternId = signal<string | null>(null);

  // Studio Interactive Synthesis
  studioInputSamples = signal<string>(
    '2026-10-04 10:15:30 AUTH_FAIL user=attacker src=198.51.100.99 reason=bad_pass\n2026-10-04 10:15:32 AUTH_FAIL user=admin src=203.0.113.15 reason=account_locked'
  );
  studioCustomPrompt = signal<string>('');
  studioPattern = signal<string>(
    '^(?P<timestamp>\\S+ \\S+) AUTH_FAIL user=(?P<user>\\S+) src=(?P<src_ip>\\S+) reason=(?P<reason>\\S+)$'
  );
  studioTestLog = signal<string>(
    '2026-10-04 10:16:00 AUTH_FAIL user=charlie src=192.168.1.50 reason=timeout'
  );
  studioTestResult = signal<ParserTestResult | null>(null);
  studioIsSynthesizing = signal<boolean>(false);
  studioIsTesting = signal<boolean>(false);
  studioMessage = signal<string | null>(null);
  /** A failed load / toggle / delete, shown on the page. */
  pageError = signal<string | null>(null);

  filteredParsers = computed(() => {
    const list = this.parsers();
    const q = this.searchQuery().toLowerCase().trim();
    if (!q) return list;
    return list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.pattern.toLowerCase().includes(q) ||
      (p.parser_type && p.parser_type.toLowerCase().includes(q)) ||
      (p.fingerprint_signature && p.fingerprint_signature.toLowerCase().includes(q)) ||
      (p.fields && p.fields.some(f => f.name.toLowerCase().includes(q)))
    );
  });

  ngOnInit() {
    this.loadParsers();
  }

  private fail(what: string, e: any) {
    this.pageError.set(`${what}: ${e?.error?.message || e?.error?.error || e?.message || 'request failed'}`);
  }

  loadParsers() {
    this.pageError.set(null);
    this.siem.getParsers().subscribe({
      next: (list) => {
        this.parsers.set(list);
        if (list.length > 0 && !this.selectedParser()) {
          this.selectedParser.set(list[0]);
        }
      },
      error: (e) => this.fail('Could not load the parsers', e)
    });

    this.siem.getParserStats().subscribe({
      next: (stats) => this.parserStats.set(stats),
      error: (e) => this.fail('Could not load the parser statistics', e)
    });

    this.siem.getUnmatchedFingerprints().subscribe({
      next: (unmatched) => this.unmatchedFingerprints.set(unmatched),
      error: (e) => this.fail('Could not load the unmatched log formats', e)
    });
  }

  copyPattern(pattern: string, id: string) {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(pattern);
      this.copiedPatternId.set(id);
      setTimeout(() => this.copiedPatternId.set(null), 1800);
    }
  }

  getRemainingFields(p: DynamicParser): string {
    if (!p.fields || p.fields.length <= 3) return '';
    return p.fields.slice(3).map(f => `${f.name}: ${f.field_type}`).join(', ');
  }

  toggleParserStatus(p: DynamicParser) {
    const newStatus = p.status === 'Active' ? 'Disabled' : 'Active';
    const updated = { ...p, status: newStatus as any };
    this.siem.updateParser(p.id, updated).subscribe({
      next: () => {
        this.parsers.update(list => list.map(item => item.id === p.id ? updated : item));
      },
      error: (e) => this.fail(`Could not ${newStatus === 'Active' ? 'enable' : 'disable'} "${p.name}"`, e)
    });
  }

  deleteParser(id: string) {
    if (!confirm('Are you sure you want to delete this reusable parser?')) return;
    this.siem.deleteParser(id).subscribe({
      next: () => {
        this.parsers.update(list => list.filter(p => p.id !== id));
        if (this.selectedParser()?.id === id) {
          this.selectedParser.set(null);
        }
      },
      error: (e) => this.fail('Could not delete the parser', e)
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
      samples: rawSamples,
      instructions: this.studioCustomPrompt().trim() || undefined
    }).subscribe({
      next: (res) => {
        this.studioIsSynthesizing.set(false);
        if (res.parser) {
          this.selectedParser.set(res.parser);
          this.studioPattern.set(res.parser.pattern);
          this.studioMessage.set(`✓ Synthesized parser "${res.parser.name}" with ${(res.parser.confidence * 100).toFixed(0)}% confidence!`);
          this.loadParsers();
          if (res.parser.sample_logs && res.parser.sample_logs.length > 0) {
            this.studioTestLog.set(res.parser.sample_logs[0]);
            this.testParserPattern();
          }
        } else if (res.pattern) {
          this.studioPattern.set(res.pattern);
          this.studioMessage.set(`✓ Synthesized regex pattern with ${(res.confidence * 100).toFixed(0)}% confidence!`);
          this.loadParsers();
        }
      },
      error: (err) => {
        this.studioIsSynthesizing.set(false);
        this.studioMessage.set(`Synthesis failed: ${err.error?.message || err.error?.error || err.message || 'request failed'}`);
      }
    });
  }

  testParserPattern() {
    const pat = this.studioPattern().trim();
    const raw = this.studioTestLog().trim();
    if (!pat || !raw) return;

    this.studioIsTesting.set(true);
    this.siem.testParser(pat, raw).subscribe({
      // the server compiles the pattern with the same regex engine the parsers run on
      next: (res) => {
        this.studioIsTesting.set(false);
        this.studioTestResult.set(res?.result ?? res);
      },
      error: (e) => {
        this.studioIsTesting.set(false);
        this.studioTestResult.set({
          success: false,
          matches_count: 0,
          total_samples: 1,
          extracted_fields: {},
          execution_time_us: 0,
          error: e?.error?.error || e?.error?.message || e?.message || 'The test request failed'
        });
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
