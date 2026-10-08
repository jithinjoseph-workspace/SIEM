import {
  Component, Input, OnInit, OnDestroy, AfterViewInit, ElementRef, ViewChild,
  ChangeDetectionStrategy, signal, computed, ViewEncapsulation, inject, NgZone
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import {
  LucideAngularModule,
  Activity, RefreshCw, XCircle, AlertCircle, Server, Search,
  Check, User, Laptop, Terminal, MapPin,
  ZoomIn, ZoomOut, RotateCcw, Globe, Shield, Radio, Sparkles
} from 'lucide-angular';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

export interface SessionPin {
  username: string;
  ip: string;
  device: string;
  city: string;
  country: string;
  lat: number;
  lon: number;
  loginTime: string;
  role: string;
}

@Component({
  selector: 'app-sessions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './sessions.html',
  styleUrl: './sessions.css',
})
export class Sessions implements OnInit, OnDestroy, AfterViewInit {
  @Input() tenantId = '';

  private api = inject(Api);
  private auth = inject(AuthService);
  private http = inject(HttpClient);
  private ngZone = inject(NgZone);

  @ViewChild('globeCanvasRef', { static: false }) globeCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('globeContainerRef', { static: false }) globeContainerRef!: ElementRef<HTMLDivElement>;

  // Lucide Icons
  readonly ActivityIcon = Activity;
  readonly RefreshCwIcon = RefreshCw;
  readonly XCircleIcon = XCircle;
  readonly AlertCircleIcon = AlertCircle;
  readonly ServerIcon = Server;
  readonly SearchIcon = Search;
  readonly CheckIcon = Check;
  readonly UserIcon = User;
  readonly LaptopIcon = Laptop;
  readonly TerminalIcon = Terminal;
  readonly MapPinIcon = MapPin;
  readonly ZoomInIcon = ZoomIn;
  readonly ZoomOutIcon = ZoomOut;
  readonly RotateCcwIcon = RotateCcw;
  readonly GlobeIcon = Globe;
  readonly ShieldIcon = Shield;
  readonly RadioIcon = Radio;
  readonly SparklesIcon = Sparkles;

  // Search — filters the session list below by username, device, or IP.
  readonly searchQuery = signal('');

  // Active Sessions State
  readonly activeSessions = signal<any[]>([]);
  readonly sessionsLoading = signal(false);
  readonly sessionsGrouped = signal<Record<string, any[]>>({});
  readonly sessionPins = signal<SessionPin[]>([]);
  readonly hoveredPin = signal<SessionPin | null>(null);
  // Other sessions sharing the exact same IP as hoveredPin — they land on the
  // identical lat/lon and would otherwise render as one dot with only the
  // first session's info reachable by hover, silently hiding the rest.
  readonly hoveredGroup = signal<SessionPin[]>([]);
  readonly selectedPin = signal<SessionPin | null>(null);

  // Session Termination State
  readonly forceLogoutConfirmUser = signal('');
  readonly forceLogoutDeviceKey = signal('');
  readonly message = signal('');
  readonly messageType = signal<'success' | 'error'>('success');
  readonly showSessionsDrawer = signal(false);

  // Continent presets for quick focus
  readonly continents = [
    { id: 'world', name: 'World', rot: [0, -18, 0] as [number, number, number] },
    { id: 'na', name: 'N. America', rot: [100, -38, 0] as [number, number, number] },
    { id: 'sa', name: 'S. America', rot: [60, 20, 0] as [number, number, number] },
    { id: 'eu', name: 'Europe', rot: [-15, -50, 0] as [number, number, number] },
    { id: 'africa', name: 'Africa', rot: [-20, 5, 0] as [number, number, number] },
    { id: 'asia', name: 'Asia', rot: [-95, -28, 0] as [number, number, number] },
    { id: 'oceania', name: 'Oceania', rot: [-135, 25, 0] as [number, number, number] },
  ];
  selectedContinent = 'world';

  // 3D Orthographic Earth Globe State
  private globeRot: [number, number, number] = [0, -18, 0];
  private targetGlobeRot: [number, number, number] | null = null;
  private globeScale = 1.0;
  private targetGlobeScale = 1.0;
  isAutoRotating = true;
  private isDragging = false;
  private dragStart: { x: number; y: number } | null = null;
  private rotStart: [number, number, number] = [0, -18, 0];
  tooltipPos = { x: 0, y: 0 };

  private animTick = 0;
  private rafId: number | null = null;
  private resizeObserver: ResizeObserver | null = null;

  // Cartographic features from TopoJSON
  private cachedWorldData: any = null;
  private landFeature: any = null;
  private countryBorders: any = null;
  private graticule = d3.geoGraticule().step([18, 18])();

  ngOnInit() {
    if (!this.tenantId) {
      this.tenantId = this.auth.getUser()?.tenant_id || 'default';
    }
    this.loadWorldData();
    this.loadActiveSessions();
  }

  ngAfterViewInit() {
    this.setupInteractionListeners();
    this.setupResizeObserver();
    this.ngZone.runOutsideAngular(() => {
      this.animateGlobe();
    });
  }

  ngOnDestroy() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
  }

  // ── TopoJSON World Map Loading ──
  private loadWorldData() {
    this.http.get('/assets/world-110m.json').subscribe({
      next: (data: any) => {
        this.cachedWorldData = data;
        try {
          this.countryBorders = (topojson as any).mesh(data, data.objects.countries, (a: any, b: any) => a !== b);
          if (data.objects.land) {
            this.landFeature = (topojson as any).feature(data, data.objects.land);
          } else if (data.objects.countries) {
            this.landFeature = (topojson as any).feature(data, data.objects.countries);
          }
        } catch (e) {
          console.error('Error parsing world data:', e);
        }
      },
      error: (err) => {
        console.warn('Could not load /assets/world-110m.json', err);
      }
    });
  }

  // ── Session Loading & Geocoding ──
  loadActiveSessions() {
    this.sessionsLoading.set(true);
    this.api.getActiveSessions().subscribe({
      next: (data: any) => {
        const sessions: any[] = data.sessions || [];

        const grouped: Record<string, any[]> = {};
        for (const s of sessions) {
          if (!grouped[s.username]) grouped[s.username] = [];
          grouped[s.username].push(s);
        }
        this.activeSessions.set(sessions);
        this.sessionsGrouped.set(grouped);
        this.sessionsLoading.set(false);

        // Map sessions to real-world pins
        this.geocodeSessions(sessions);
      },
      error: () => {
        this.sessionsLoading.set(false);
      }
    });
  }

  // Real geolocation via GeoLite2-City DB (+ ip-api.com fallback)
  // Private/unresolvable IPs default to corporate SOC hub coordinates so they are still visible
  private geocodeSessions(sessions: any[]) {
    const ips = [...new Set(sessions.map(s => s.ip).filter((ip: string) => !!ip))];
    if (!ips.length) {
      this.sessionPins.set([]);
      return;
    }

    this.api.geoLookup(ips).subscribe({
      next: (res: any) => {
        const geoByIp = new Map<string, any>();
        for (const r of (res?.results || [])) {
          if (r.status === 'success' || (r.lat && r.lon)) geoByIp.set(r.query, r);
        }

        const pins: SessionPin[] = sessions
          .map((s): SessionPin | null => {
            let geo = geoByIp.get(s.ip);
            // If local or private IP, provide default primary gateway coordinates so local sessions are placed accurately
            if (!geo && (s.ip === '127.0.0.1' || s.ip === 'localhost' || s.ip?.startsWith('192.168.') || s.ip?.startsWith('10.') || s.ip?.startsWith('172.'))) {
              geo = {
                lat: 28.6139,
                lon: 77.2090,
                city: 'Corporate HQ (Local Gateway)',
                countryCode: 'IN'
              };
            }
            if (!geo || typeof geo.lat !== 'number' || typeof geo.lon !== 'number') return null;
            return {
              username: s.username,
              ip: s.ip || '—',
              device: s.device || 'Unknown Device',
              city: geo.city || geo.country || 'Unknown',
              country: geo.countryCode || '',
              lat: geo.lat,
              lon: geo.lon,
              loginTime: this.formatLoginTime(s.login_time),
              role: s.role || 'User',
            };
          })
          .filter((p): p is SessionPin => p !== null);

        this.sessionPins.set(pins);
      },
      error: () => {
        this.sessionPins.set([]);
      },
    });
  }

  // ── Globe HUD Controls ──
  focusContinent(id: string) {
    this.selectedContinent = id;
    const c = this.continents.find(item => item.id === id);
    if (c) {
      this.targetGlobeRot = [...c.rot];
    }
  }

  zoomIn() {
    this.targetGlobeScale = Math.min(3.5, this.targetGlobeScale * 1.25);
  }

  zoomOut() {
    this.targetGlobeScale = Math.max(0.75, this.targetGlobeScale * 0.8);
  }

  resetView() {
    this.targetGlobeRot = [0, -18, 0];
    this.targetGlobeScale = 1.0;
    this.selectedContinent = 'world';
  }

  toggleAutoRotation() {
    this.isAutoRotating = !this.isAutoRotating;
  }

  countryFlag(code: string): string {
    if (!code || code.length !== 2) return '🌐';
    return code.toUpperCase().replace(/./g, c =>
      String.fromCodePoint(127397 + c.charCodeAt(0))
    );
  }

  // ── 3D Earth Animation Loop ──
  private animateGlobe() {
    this.rafId = requestAnimationFrame(() => this.animateGlobe());
    this.animTick++;

    // 1. Camera target rotation lerp
    if (this.targetGlobeRot) {
      const dRot0 = ((this.targetGlobeRot[0] - this.globeRot[0] + 540) % 360) - 180;
      const dRot1 = this.targetGlobeRot[1] - this.globeRot[1];
      this.globeRot[0] += dRot0 * 0.08;
      this.globeRot[1] += dRot1 * 0.08;
      if (Math.abs(dRot0) < 0.2 && Math.abs(dRot1) < 0.2) {
        this.targetGlobeRot = null;
      }
    } else if (!this.isDragging && this.isAutoRotating && !this.hoveredPin()) {
      this.globeRot[0] += 0.1; // Smooth continuous Earth rotation
    }

    // 2. Zoom scale lerp
    this.globeScale += (this.targetGlobeScale - this.globeScale) * 0.12;

    this.renderCanvas();
  }

  // ── Canvas Rendering Engine (Pure Orthographic Vector Earth) ──
  private renderCanvas() {
    const canvas = this.globeCanvasRef?.nativeElement;
    const container = this.globeContainerRef?.nativeElement;
    if (!canvas || !container) return;

    const W = container.clientWidth || 700;
    const H = container.clientHeight || 520;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      canvas.style.width = `${W}px`;
      canvas.style.height = `${H}px`;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    const baseR = Math.min(W, H) * 0.44;
    const currentR = baseR * this.globeScale;

    // Orthographic 3D Projection
    const proj = d3.geoOrthographic()
      .scale(currentR)
      .translate([W / 2, H / 2])
      .clipAngle(90)
      .rotate(this.globeRot);

    const pCtx = d3.geoPath().projection(proj).context(ctx);

    const isFrontHemi = (lonLat: [number, number]) => {
      return d3.geoDistance(lonLat, [-this.globeRot[0], -this.globeRot[1]]) < Math.PI / 2;
    };

    // ── 1. Outer Atmospheric Halo Glow ──
    const atmoGrad = ctx.createRadialGradient(W / 2, H / 2, currentR * 0.85, W / 2, H / 2, currentR * 1.26);
    atmoGrad.addColorStop(0, 'rgba(34, 211, 238, 0.22)');
    atmoGrad.addColorStop(0.4, 'rgba(6, 182, 212, 0.08)');
    atmoGrad.addColorStop(1, 'rgba(2, 6, 23, 0)');

    ctx.beginPath();
    ctx.arc(W / 2, H / 2, currentR * 1.25, 0, Math.PI * 2);
    ctx.fillStyle = atmoGrad;
    ctx.fill();

    // ── 2. Earth Deep Cyber Ocean Sphere ──
    const oceanGrad = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, currentR * 1.05);
    oceanGrad.addColorStop(0, '#09152b');
    oceanGrad.addColorStop(0.65, '#050d1b');
    oceanGrad.addColorStop(1, '#02050c');

    ctx.beginPath();
    pCtx({ type: 'Sphere' } as any);
    ctx.fillStyle = oceanGrad;
    ctx.fill();

    // ── 3. Subtle Latitude & Longitude Graticule Lines ──
    ctx.beginPath();
    pCtx(this.graticule);
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.08)';
    ctx.lineWidth = 0.5;
    ctx.stroke();

    // ── 4. Real Continents & Landmasses ──
    if (this.landFeature) {
      ctx.beginPath();
      pCtx(this.landFeature);
      ctx.fillStyle = '#0f223d';
      ctx.fill();
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.42)';
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }

    // ── 5. Real World Country Borders (Thin, Crisp Cyber Lines) ──
    if (this.countryBorders) {
      ctx.beginPath();
      pCtx(this.countryBorders);
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.2)';
      ctx.lineWidth = 0.45;
      ctx.stroke();
    }

    // ── 6. Earth Horizon Rim Glow ──
    ctx.beginPath();
    pCtx({ type: 'Sphere' } as any);
    ctx.strokeStyle = 'rgba(34, 211, 238, 0.55)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // ── 7. Great Circle Telemetry Arcs between Sessions ──
    const pins = this.sessionPins();
    if (pins.length > 1) {
      for (let i = 0; i < pins.length - 1; i++) {
        const p1: [number, number] = [pins[i].lon, pins[i].lat];
        const p2: [number, number] = [pins[i + 1].lon, pins[i + 1].lat];
        this.drawGreatCircleArc(ctx, proj, isFrontHemi, p1, p2);
      }
      if (pins.length > 2) {
        const pFirst: [number, number] = [pins[0].lon, pins[0].lat];
        const pLast: [number, number] = [pins[pins.length - 1].lon, pins[pins.length - 1].lat];
        this.drawGreatCircleArc(ctx, proj, isFrontHemi, pLast, pFirst);
      }
    }

    // ── 8. Real-World Session Pins & Thin Modern Icons ──
    pins.forEach((pin, i) => {
      const pt: [number, number] = [pin.lon, pin.lat];
      if (!isFrontHemi(pt)) return;

      const xy = proj(pt);
      if (!xy) return;

      // Compare by IP only (not username too) — sessions sharing an IP sit at
      // the same coordinates and should highlight together, not just the one
      // that happened to win the hover hit-test.
      const isHovered = !!this.hoveredPin() && this.hoveredPin()?.ip === pin.ip;

      // Concentric pulsing radar waves
      const pulse = (this.animTick * 0.035 + i * 0.35) % 1;
      const rPulse = 5 + pulse * 14;
      const alphaPulse = (1 - pulse) * 0.85;

      ctx.beginPath();
      ctx.arc(xy[0], xy[1], rPulse, 0, Math.PI * 2);
      ctx.strokeStyle = isHovered ? `rgba(244, 63, 94, ${alphaPulse})` : `rgba(34, 211, 238, ${alphaPulse})`;
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // Outer Anchor Halo
      ctx.beginPath();
      ctx.arc(xy[0], xy[1], isHovered ? 6.5 : 4.5, 0, Math.PI * 2);
      ctx.fillStyle = isHovered ? 'rgba(244, 63, 94, 0.4)' : 'rgba(34, 211, 238, 0.35)';
      ctx.fill();

      // Pinpoint Core Dot
      ctx.beginPath();
      ctx.arc(xy[0], xy[1], isHovered ? 3.5 : 2.6, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();

      // Micro City / Country Tag Badge (Thin Icon Styling)
      const label = `${pin.city}`;
      ctx.font = '600 9px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace';
      const textWidth = ctx.measureText(label).width;
      const bx = xy[0] + 7;
      const by = xy[1] - 7;

      ctx.fillStyle = isHovered ? 'rgba(30, 10, 20, 0.9)' : 'rgba(6, 12, 23, 0.82)';
      ctx.strokeStyle = isHovered ? 'rgba(244, 63, 94, 0.6)' : 'rgba(34, 211, 238, 0.35)';
      ctx.lineWidth = 0.8;
      this.drawRoundedRect(ctx, bx - 3, by - 9, textWidth + 6, 12, 3);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = isHovered ? '#fb7185' : '#22d3ee';
      ctx.fillText(label, bx, by);
    });

    ctx.restore();
  }

  // Draw Great Circle flight path with traveling photon light packet
  private drawGreatCircleArc(
    ctx: CanvasRenderingContext2D,
    proj: d3.GeoProjection,
    isFrontHemi: (pt: [number, number]) => boolean,
    p1: [number, number],
    p2: [number, number]
  ) {
    const interp = d3.geoInterpolate(p1, p2);
    ctx.beginPath();
    let first = true;
    const steps = 24;

    for (let s = 0; s <= steps; s++) {
      const pt = interp(s / steps) as [number, number];
      if (isFrontHemi(pt)) {
        const xy = proj(pt);
        if (xy) {
          if (first) {
            ctx.moveTo(xy[0], xy[1]);
            first = false;
          } else {
            ctx.lineTo(xy[0], xy[1]);
          }
        }
      } else {
        first = true;
      }
    }
    ctx.strokeStyle = 'rgba(34, 211, 238, 0.28)';
    ctx.lineWidth = 1.0;
    ctx.setLineDash([3, 4]);
    ctx.stroke();
    ctx.setLineDash([]);

    // Animated Flying Photon Packet
    const t = (this.animTick * 0.008) % 1;
    const photonPt = interp(t) as [number, number];
    if (isFrontHemi(photonPt)) {
      const pxy = proj(photonPt);
      if (pxy) {
        ctx.beginPath();
        ctx.arc(pxy[0], pxy[1], 2.2, 0, Math.PI * 2);
        ctx.fillStyle = '#38bdf8';
        ctx.shadowColor = '#00f2fe';
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  private drawRoundedRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  // ── Interaction Listeners (Drag, Zoom, Proximity Hover) ──
  private setupInteractionListeners() {
    const canvas = this.globeCanvasRef?.nativeElement;
    const container = this.globeContainerRef?.nativeElement;
    if (!canvas || !container) return;

    canvas.addEventListener('mousedown', (e: MouseEvent) => {
      this.isDragging = true;
      this.targetGlobeRot = null;
      this.dragStart = { x: e.clientX, y: e.clientY };
      this.rotStart = [...this.globeRot] as [number, number, number];
      canvas.style.cursor = 'grabbing';
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
      this.dragStart = null;
      if (canvas) canvas.style.cursor = 'grab';
    });

    canvas.addEventListener('mousemove', (e: MouseEvent) => {
      if (this.isDragging && this.dragStart) {
        const sens = 0.35 / Math.max(1, this.globeScale * 0.7);
        this.globeRot[0] = this.rotStart[0] + (e.clientX - this.dragStart.x) * sens;
        this.globeRot[1] = Math.max(-75, Math.min(75, this.rotStart[1] - (e.clientY - this.dragStart.y) * sens));
      } else {
        this.checkPinHover(e, canvas);
      }
    });

    canvas.addEventListener('mouseleave', () => {
      this.isDragging = false;
      this.dragStart = null;
      this.hoveredPin.set(null);
      this.hoveredGroup.set([]);
    });

    canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      this.targetGlobeScale = Math.max(0.75, Math.min(3.5, this.targetGlobeScale * factor));
    }, { passive: false });
  }

  private checkPinHover(e: MouseEvent, canvas: HTMLCanvasElement) {
    const container = this.globeContainerRef?.nativeElement;
    if (!container) return;

    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const W = container.clientWidth || 700;
    const H = container.clientHeight || 520;
    const baseR = Math.min(W, H) * 0.44;
    const currentR = baseR * this.globeScale;

    const proj = d3.geoOrthographic()
      .scale(currentR)
      .translate([W / 2, H / 2])
      .clipAngle(90)
      .rotate(this.globeRot);

    let foundPin: SessionPin | null = null;
    let minDistance = 16;
    let pinScreenPos = { x: 0, y: 0 };

    for (const pin of this.sessionPins()) {
      const pt: [number, number] = [pin.lon, pin.lat];
      const distToFront = d3.geoDistance(pt, [-this.globeRot[0], -this.globeRot[1]]);
      if (distToFront >= Math.PI / 2) continue;

      const xy = proj(pt);
      if (!xy) continue;

      const dist = Math.hypot(mx - xy[0], my - xy[1]);
      if (dist < minDistance) {
        minDistance = dist;
        foundPin = pin;
        pinScreenPos = { x: xy[0], y: xy[1] };
      }
    }

    if (foundPin) {
      this.hoveredPin.set(foundPin);
      this.hoveredGroup.set(this.sessionPins().filter(p => p.ip === foundPin!.ip));
      canvas.style.cursor = 'pointer';

      // Keep tooltip positioned within container bounds
      const tx = Math.min(W - 250, Math.max(12, pinScreenPos.x + 14));
      const ty = Math.min(H - 160, Math.max(12, pinScreenPos.y - 45));
      this.tooltipPos = { x: tx, y: ty };
    } else {
      this.hoveredPin.set(null);
      this.hoveredGroup.set([]);
      canvas.style.cursor = this.isDragging ? 'grabbing' : 'grab';
    }
  }

  private setupResizeObserver() {
    const container = this.globeContainerRef?.nativeElement;
    if (!container) return;

    this.resizeObserver = new ResizeObserver(() => {
      this.renderCanvas();
    });
    this.resizeObserver.observe(container);
  }

  // ── Session Table Management Helpers ──
  trackByUsername(_: number, name: string): string {
    return name;
  }

  trackByIndex(i: number): number {
    return i;
  }

  sessionUsernames(): string[] {
    const q = this.searchQuery().trim().toLowerCase();
    const names = Object.keys(this.sessionsGrouped()).sort();
    if (!q) return names;
    return names.filter(name => {
      if (name.toLowerCase().includes(q)) return true;
      return (this.sessionsGrouped()[name] || []).some((s: any) =>
        (s.ip || '').toLowerCase().includes(q) || (s.device || '').toLowerCase().includes(q)
      );
    });
  }

  groupedDevices(username: string): { device: string; ip: string; latestTime: string; count: number }[] {
    const sessions = this.sessionsGrouped()[username] || [];
    const map: Record<string, { device: string; ip: string; latestTime: string; count: number }> = {};
    for (const s of sessions) {
      const key = `${s.device}|${s.ip}`;
      if (!map[key]) {
        map[key] = { device: s.device || 'Unknown', ip: s.ip || '—', latestTime: s.login_time, count: 0 };
      }
      map[key].count++;
      if (s.login_time > map[key].latestTime) map[key].latestTime = s.login_time;
    }
    return Object.values(map).sort((a, b) => b.latestTime.localeCompare(a.latestTime));
  }

  promptForceLogout(username: string) {
    this.forceLogoutConfirmUser.set(username);
  }

  cancelForceLogout() {
    this.forceLogoutConfirmUser.set('');
  }

  promptForceLogoutDevice(username: string, ip: string, device: string) {
    this.forceLogoutDeviceKey.set(`${username}|${ip}|${device}`);
  }

  cancelForceLogoutDevice() {
    this.forceLogoutDeviceKey.set('');
  }

  confirmForceLogoutDevice(username: string, ip: string, device: string) {
    this.api.forceLogoutDevice(username, ip, device).subscribe({
      next: (data: any) => {
        this.forceLogoutDeviceKey.set('');
        this.showMessage(`Signed out ${device} (${ip}) — ${data.sessions_terminated} session(s) terminated`, 'success');
        this.loadActiveSessions();
      },
      error: () => {
        this.showMessage('Failed to sign out device', 'error');
        this.forceLogoutDeviceKey.set('');
      },
    });
  }

  confirmForceLogout(username: string) {
    this.api.forceLogoutUser(username).subscribe({
      next: (data: any) => {
        this.forceLogoutConfirmUser.set('');
        this.showMessage(`${username} signed out from ${data.sessions_terminated} device(s)`, 'success');
        this.loadActiveSessions();
      },
      error: () => {
        this.showMessage('Failed to sign out user', 'error');
        this.forceLogoutConfirmUser.set('');
      }
    });
  }

  formatLoginTime(ts: string): string {
    if (!ts) return '—';
    const num = parseInt(ts, 10);
    if (isNaN(num)) return ts;
    return new Date(num * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
  }

  toggleSessionsDrawer() {
    this.showSessionsDrawer.update(v => !v);
  }
}
