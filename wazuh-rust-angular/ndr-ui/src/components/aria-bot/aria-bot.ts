import {
  Component, OnInit, OnDestroy, AfterViewInit,
  ViewChild, ElementRef, ChangeDetectorRef, HostListener
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { interval, Subscription } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { DotLottie } from '@lottiefiles/dotlottie-web';

interface ChatMessage {
  role: 'user' | 'bot';
  content: string;
  timestamp: Date;
  alertCard?: AlertCard;
  actions?: ChatAction[];
}

interface AlertCard {
  severity: string;
  src_ip: string;
  dst_ip: string;
  /** the alert id */
  community_id: string;
  agent?: string;
  rule_name?: string;
  score?: number;
}

interface ChatAction {
  label: string;
  icon: string;
  action: string;
  data?: any;
}

const SEGMENTS = {
  idle: { start: 0, end: 29, loop: true },
  yes: { start: 31, end: 104, loop: false },
  no: { start: 106, end: 179, loop: false },
  alert: { start: 181, end: 269, loop: false },
  thinking: { start: 271, end: 389, loop: false },
  jump: { start: 391, end: 478, loop: false },
};

const EMOTION_MAP: Record<string, keyof typeof SEGMENTS> = {
  idle: 'idle',
  think: 'thinking',
  alert: 'alert',
  cheer: 'jump',
  wave: 'yes',
  sad: 'no',
  confirmed: 'yes',
  denied: 'no',
};

@Component({
  selector: 'app-aria-bot',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './aria-bot.html',
  styleUrl: './aria-bot.css'
})
export class AriaBot implements OnInit, AfterViewInit, OnDestroy {

  @ViewChild('lottieCanvas') lottieCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('msgContainer') msgContainer!: ElementRef;

  // ── Chat state ──
  isOpen = false;
  isTyping = false;
  inputText = '';
  messages: ChatMessage[] = [];
  history: { role: string; content: string }[] = [];

  // ── Bot state ──
  emotion = 'idle';
  isTalking = false;
  unreadCount = 0;
  speechText = '';
  showSpeech = false;
  showAlertBanner = false;
  latestAlert: AlertCard | null = null;
  isVisible = true;

  // ── Drag state ──
  isDragging = false;
  hasMoved = false;
  dragStartX = 0;
  dragStartY = 0;
  currentRight = 24;
  currentBottom = 24;
  startRight = 24;
  startBottom = 24;

  // ── Theme state ──
  botTheme: 'light' | 'dark' = 'dark';

  // ── Alert tracking ──
  criticalCount = 0;
  highCount = 0;
  lastSeenCid = '';
  lastSeenPredId = '';

  // ── Lottie ──
  private dotLottie: DotLottie | null = null;
  private segmentTimer: any = null;
  private currentSegKey: keyof typeof SEGMENTS = 'idle';

  // ── Timers/subs ──
  private pollSub?: Subscription;
  private routerSub?: Subscription;
  private talkTimer: any;
  private speechTimer: any;
  private proactiveSub?: any;

  // what ARIA really can do (it talks to the AI Copilot)
  private proactiveMessages = [
    "Ask me about your latest alerts!",
    "Want the latest critical alert?",
    "I can investigate a host, IP or user for you.",
    "Need a case and a report? Just ask.",
  ];
  /** The AI Copilot conversation ARIA continues. */
  private copilotConversation: string | null = null;
  private proactiveIndex = 0;

  quickReplies = [
    { text: 'Latest critical alert', icon: 'triangle-alert' },
    { text: 'Alerts today by severity', icon: 'activity' },
    { text: 'Which rules fire most?', icon: 'shield-alert' },
    { text: 'Open a case for the latest critical alert and tell me why', icon: 'file-text' },
  ];

  constructor(
    private http: HttpClient,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) { }

  // ── LIFECYCLE ──

  ngOnInit() {
    const savedTheme = localStorage.getItem('aria_bot_theme');
    if (savedTheme === 'light' || savedTheme === 'dark') {
      this.botTheme = savedTheme;
    }

    this.routerSub = this.router.events.subscribe((e: any) => {
      const url = e.urlAfterRedirects || e.url;
      if (url) {
        // the AI Copilot page has its own chat
        this.isVisible = !url.includes('/admin') && !url.includes('/siem-copilot');
        this.cdr.detectChanges();
      }
    });
    const initUrl = this.router.url;
    this.isVisible = !initUrl.includes('/admin') && !initUrl.includes('/siem-copilot');

    this.fetchStatus();
    this.pollSub = interval(30000).pipe(
      switchMap(() => this.httpGet('/api/aria/status'))
    ).subscribe({
      next: s => this.handleStatus(s),
      error: () => { }
    });

    // Proactive speech bubbles every 18s when chat is closed
    this.proactiveSub = setInterval(() => {
      if (!this.isOpen) {
        this.speechText = this.proactiveMessages[this.proactiveIndex];
        this.proactiveIndex = (this.proactiveIndex + 1) % this.proactiveMessages.length;
        this.showSpeech = true;
        this.cdr.detectChanges();
        clearTimeout(this.speechTimer);
        this.speechTimer = setTimeout(() => {
          this.showSpeech = false;
          this.cdr.detectChanges();
        }, 6000);
      }
    }, 18000);
  }

  ngAfterViewInit() {
    setTimeout(() => this.initLottie(), 300);
  }

  ngOnDestroy() {
    this.pollSub?.unsubscribe();
    this.routerSub?.unsubscribe();
    clearInterval(this.proactiveSub);
    this.dotLottie?.destroy();
    clearTimeout(this.talkTimer);
    clearTimeout(this.speechTimer);
    clearTimeout(this.segmentTimer);
  }

  // ── LOTTIE ──

  initLottie() {
    const canvas = this.lottieCanvasRef?.nativeElement;
    if (!canvas) return;

    DotLottie.setWasmUrl('/assets/dotlottie-player.wasm');
    this.dotLottie = new DotLottie({
      canvas,
      src: '/assets/lottie/robot.json',
      loop: false,   // we control looping manually via frame listener
      autoplay: false,
      speed: 1,
    });

    this.dotLottie.addEventListener('load', () => {
      this.playSegment('idle');
      setTimeout(() => this.bootGreeting(), 1000);
    });

    // Frame listener — clamps playback to current segment boundaries
    this.dotLottie.addEventListener('frame', (e: any) => {
      const seg = SEGMENTS[this.currentSegKey];
      if (e.currentFrame >= seg.end) {
        if (seg.loop) {
          // Loop: jump back to start of segment
          this.dotLottie?.setFrame(seg.start);
          this.dotLottie?.play();
        } else {
          // One-shot: pause here, return to idle
          this.dotLottie?.pause();
          this.currentSegKey = 'idle';
          this.emotion = 'idle';
          this.playSegment('idle');
        }
      }
    });
  }

  playSegment(segKey: keyof typeof SEGMENTS, onComplete?: () => void) {
    if (!this.dotLottie) return;
    clearTimeout(this.segmentTimer);

    this.currentSegKey = segKey;
    const seg = SEGMENTS[segKey];
    this.dotLottie.setFrame(seg.start);
    this.dotLottie.setSpeed(segKey === 'alert' ? 1.3 : 1.0);
    this.dotLottie.play();

    onComplete?.();
  }

  setEmotion(e: string, onDone?: () => void) {
    this.emotion = e;
    if (e === 'alert' || e === 'idle') {
      const seg = EMOTION_MAP[e] || 'idle';
      if (this.dotLottie) this.playSegment(seg, onDone);
    } else {
      onDone?.();
    }
  }

  // ── GREETING ──

  bootGreeting() {
    this.setEmotion('wave');
    this.showSpeechBubble("Hi! I'm ARIA. Ask me about your alerts.");
    // Message added immediately so chat panel is never empty on first open
    this.addBotMessage(
      "Hi! I'm ARIA, connected to the SIEM's AI Copilot. Ask me about alerts, hosts, IPs or users. I open cases and write reports only when you ask.",
      'idle',
      []
    );
    this.cdr.detectChanges();
  }

  // ── STATUS POLLING ──

  fetchStatus() {
    this.httpGet('/api/aria/status').subscribe({
      next: s => this.handleStatus(s),
      error: () => { }
    });
  }

  handleStatus(s: any) {
    this.criticalCount = s.critical_count || 0;
    this.highCount = s.high_count || 0;

    // Real-time CRITICAL alert from live hits
    const newCid = s.latest_community_id || '';
    const sev = s.latest_severity || '';
    if (newCid && newCid !== this.lastSeenCid && sev === 'CRITICAL') {
      this.lastSeenCid = newCid;
      this.latestAlert = {
        severity: sev,
        src_ip: s.latest_src_ip || '',
        dst_ip: s.latest_dst_ip || '',
        community_id: newCid,
        rule_name: s.latest_description || '',
        agent: s.latest_agent || '',
      };
      this.onNewAlert(this.latestAlert);
    }

    // Rising prediction alert — MITRE chain probability increasing
    const predId = s.prediction_id || '';
    if (s.prediction_alert && predId && predId !== this.lastSeenPredId) {
      this.lastSeenPredId = predId;
      const pct = Math.round((s.prediction_prob || 0) * 100);
      this.setEmotion('alert');
      this.unreadCount++;
      this.showAlertBanner = true;
      this.showSpeechBubble(
        `Rising ${(s.prediction_level || '').toUpperCase()} prediction: ${s.prediction_attack} at ${pct}% probability! Click me!`
      );
      this.addBotMessage(
        `RISING THREAT DETECTED — ${s.prediction_attack} attack chain probability is at ${pct}% and increasing.\n\n${s.prediction_expl || ''}\n\nDo you want me to investigate?`,
        'alert',
        [
          { label: 'Show details', icon: '', action: 'threat_prediction', data: s },
          { label: 'View pattern match', icon: '', action: 'pattern_match', data: s },
          { label: 'Escalate now', icon: '', action: 'escalate', data: s },
        ],
        undefined
      );
    }

    this.cdr.detectChanges();
  }

  onNewAlert(alert: AlertCard) {
    this.setEmotion('alert');
    this.unreadCount++;
    this.showAlertBanner = true;
    this.showSpeechBubble(`New ${alert.severity.toLowerCase()} alert on ${alert.agent || alert.src_ip || 'a host'}. Click me!`);
    this.addBotMessage(
      `New ${alert.severity} alert${alert.agent ? ' on ' + alert.agent : ''}: ${alert.rule_name || 'see the details'}. Want me to investigate it?`,
      'alert',
      [
        { label: 'Why did it happen?', icon: '', action: 'chat', data: `Show alert ${alert.community_id} and explain why it fired` },
        { label: 'Investigate the host', icon: '', action: 'investigate', data: alert },
        { label: 'Open a case', icon: '', action: 'case', data: alert },
      ],
      alert
    );
    this.cdr.detectChanges();
  }

  // ── CHAT ──

  sendMessage(text?: string) {
    const msg = (text || this.inputText).trim();
    if (!msg || this.isTyping) return;
    this.inputText = '';

    this.messages.push({ role: 'user', content: msg, timestamp: new Date() });
    this.history.push({ role: 'user', content: msg });

    this.isTyping = true;
    this.setEmotion('think');
    this.scrollToBottom();

    // the AI Copilot answers (siem-api copilot.rs), in one conversation
    this.httpPost('/api/v1/siem/copilot', { message: msg, conversation_id: this.copilotConversation }).subscribe({
      next: (data: any) => {
        this.isTyping = false;
        this.copilotConversation = data?.conversation_id || this.copilotConversation;
        const answer = String(data?.turn?.answer || 'I had trouble answering that.')
          .replace(/\*\*(.+?)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1');
        const made = data?.turn?.artifacts || {};
        const actions: ChatAction[] = [{ label: made.report || made.case ? 'Open the case and report in Copilot' : 'Open in Copilot', icon: '', action: 'copilot', data: this.copilotConversation }];
        this.addBotMessage(answer, 'idle', actions);
        this.history.push({ role: 'assistant', content: answer });
        if (this.history.length > 20) this.history = this.history.slice(-20);
        this.cdr.detectChanges();
      },
      error: (e: any) => {
        this.isTyping = false;
        this.addBotMessage(e?.error?.message || 'The AI Copilot is not reachable right now. Try again in a moment.', 'sad');
        this.cdr.detectChanges();
      }
    });
  }

  addBotMessage(content: string, emotion: string, actions?: ChatAction[], alertCard?: AlertCard) {
    this.setEmotion(emotion);
    this.startTalking(content.length);
    this.messages = [...this.messages, { role: 'bot', content, timestamp: new Date(), alertCard, actions }];
    this.cdr.detectChanges();
    this.scrollToBottom();
  }

  // ── ACTIONS ──

  handleAction(action: ChatAction) {
    switch (action.action) {
      case 'chat':
        this.sendMessage(action.data);
        break;

      case 'investigate':
        // everything about the alert's host (or source IP)
        this.router.navigate(['/analyst/siem-investigate'], { queryParams: { q: action.data?.agent || action.data?.src_ip || '', days: 7 } });
        break;

      case 'case':
        // the Copilot opens the case with the alert as evidence, and says why
        this.router.navigate(['/analyst/siem-copilot'], { queryParams: { ask: `Open a case for alert ${action.data?.community_id}, collect the evidence and tell me why it happened` } });
        break;

      case 'copilot':
        this.router.navigate(['/analyst/siem-copilot'], { queryParams: action.data ? { c: action.data } : {} });
        break;

      case 'navigate':
        this.router.navigate([action.data]);
        break;

      default:
        this.sendMessage(action.label);
    }
  }

  handleAlertCardClick(alert: AlertCard) {
    this.setEmotion('alert');
    this.addBotMessage(
      `${alert.severity} alert${alert.agent ? ' on ' + alert.agent : ''}: ${alert.rule_name || ''}. What should I do?`,
      'alert',
      [
        { label: 'Why did it happen?', icon: '', action: 'chat', data: `Show alert ${alert.community_id} and explain why it fired` },
        { label: 'Investigate the host', icon: '', action: 'investigate', data: alert },
        { label: 'Open a case', icon: '', action: 'case', data: alert },
      ]
    );
  }

  dismissAlertBanner() { this.showAlertBanner = false; }

  toggleTheme(event?: Event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.botTheme = this.botTheme === 'light' ? 'dark' : 'light';
    localStorage.setItem('aria_bot_theme', this.botTheme);
    this.cdr.detectChanges();
  }

  closeChat(event?: Event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.isOpen = false;
    this.hasMoved = false;
  }

  goToAlerts() {
    this.showAlertBanner = false;
    this.router.navigate(['/analyst/siem-classic/console/alerts']);
  }

  // ── UI HELPERS ──

  toggleChat() {
    if (this.hasMoved) {
      this.hasMoved = false;
      return;
    }
    this.isOpen = !this.isOpen;
    if (this.isOpen) {
      this.unreadCount = 0;
      this.showSpeech = false;
      setTimeout(() => this.scrollToBottom(), 100);
    }
  }


  // ── DRAGGING ──

  @HostListener('document:pointermove', ['$event'])
  onPointerMove(event: PointerEvent) {
    if (!this.isDragging) return;
    const dx = event.clientX - this.dragStartX;
    const dy = event.clientY - this.dragStartY;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      this.hasMoved = true;
    }
    this.currentRight = this.startRight - dx;
    this.currentBottom = this.startBottom - dy;
    this.cdr.detectChanges();
  }

  @HostListener('document:pointerup', ['$event'])
  onPointerUp(event: PointerEvent) {
    if (this.isDragging) {
      this.isDragging = false;
    }
  }

  onBotPointerDown(event: PointerEvent) {
    if (event.button !== 0) return;

    const t = event.target as HTMLElement;
    if (t.closest('.header-actions') || t.closest('button')) {
      return; // Do not drag if clicking action buttons
    }

    this.isDragging = true;
    this.hasMoved = false;
    this.dragStartX = event.clientX;
    this.dragStartY = event.clientY;
    this.startRight = this.currentRight;
    this.startBottom = this.currentBottom;
    const target = event.currentTarget as HTMLElement;
    if (target.setPointerCapture) target.setPointerCapture(event.pointerId);
    event.preventDefault();
  }

  startTalking(textLen: number) {
    this.isTalking = true;
    clearTimeout(this.talkTimer);
    this.talkTimer = setTimeout(() => {
      this.isTalking = false;
      this.cdr.detectChanges();
    }, Math.max(1200, textLen * 35));
  }

  showSpeechBubble(text: string) {
    this.speechText = text;
    this.showSpeech = true;
    this.cdr.detectChanges();
    clearTimeout(this.speechTimer);
    this.speechTimer = setTimeout(() => {
      this.showSpeech = false;
      this.cdr.detectChanges();
    }, 7000);
  }

  scrollToBottom() {
    setTimeout(() => {
      const el = this.msgContainer?.nativeElement;
      if (el) el.scrollTop = el.scrollHeight;
    }, 80);
  }

  onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
  }

  getUserInitials(): string {
    return (localStorage.getItem('username') || 'US').substring(0, 2).toUpperCase();
  }

  get moodLabel(): string {
    const m: Record<string, string> = {
      idle: 'All systems nominal',
      wave: 'Saying hello',
      alert: 'Alert detected!',
      think: 'Analyzing...',
      cheer: 'Threat resolved!',
      sad: 'Worried',
    };
    return m[this.emotion] || m['idle'];
  }

  get statusColor(): string {
    if (this.criticalCount > 0) return '#ef4444';
    if (this.highCount > 0) return '#f59e0b';
    return '#22c55e';
  }

  // ── HTTP ──

  private httpGet(url: string) {
    return this.http.get<any>(url);
  }

  private httpPost(url: string, body: any) {
    return this.http.post<any>(url, body);
  }

  sanitizeRuleName(name: any): string {
    return String(name || '')
      .replace(/\bSURICATA\b/gi, 'Agent-S')
      .replace(/\bZEEK\b/gi, 'Agent-Z');
  }
}
