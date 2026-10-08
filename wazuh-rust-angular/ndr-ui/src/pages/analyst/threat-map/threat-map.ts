import { Component, OnInit, OnDestroy, ElementRef, ViewChild, HostListener, NgZone, ChangeDetectorRef, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';

import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import { LucideAngularModule, Radio, Shield, Target, TrendingUp } from 'lucide-angular';

export interface AttackSource {
  country: string;
  code: string;
  lat: number;
  lon: number;
  count: number;
  color: string;
  attacks?: { tag: string; count: number }[];
}

const ARC_COLORS = [
  '#f43f5e', '#fb7185', '#e11d48', '#be123c',
  '#f97316', '#ef4444', '#dc2626', '#fbbf24',
];

@Component({
  selector: 'app-threat-map',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './threat-map.html',
  styleUrl: './threat-map.css',
})
export class ThreatMap implements OnInit, OnDestroy {
  @ViewChild('mapContainer', { static: true }) mapRef!: ElementRef;

  attackSources: AttackSource[] = [];
  totalAttacks = 0;
  loading = true;
  selectedCountry: AttackSource | null = null;
  @Input() previewMode = false;

  RadarIcon  = Radio;
  ShieldIcon = Shield;
  TargetIcon = Target;
  TrendIcon  = TrendingUp;

  private rafId?: number;
  private resizeTimer?: ReturnType<typeof setTimeout>;
  private initSeq = 0;
  private cachedWorld: any = null;
  mapMode: 'flat' | 'globe' = 'globe';
  sourceMode: 'traffic' | 'intel' = 'traffic';

  continents = [
    { id: 'world', name: 'World', rot: [0, -20, 0], tx: 0, ty: 0 },
    { id: 'na', name: 'N. America', rot: [100, -40, 0], tx: 0.33, ty: 0.25 },
    { id: 'sa', name: 'S. America', rot: [60, 20, 0], tx: 0.25, ty: -0.25 },
    { id: 'eu', name: 'Europe', rot: [-15, -50, 0], tx: 0.08, ty: 0.33 },
    { id: 'africa', name: 'Africa', rot: [-20, 10, 0], tx: 0.08, ty: 0 },
    { id: 'asia', name: 'Asia', rot: [-90, -30, 0], tx: -0.25, ty: 0.16 },
    { id: 'oceania', name: 'Oceania', rot: [-140, 25, 0], tx: -0.33, ty: -0.25 },
    { id: 'antarctica', name: 'Antarctica', rot: [0, 80, 0], tx: 0, ty: -0.4 }
  ];
  selectedContinent = 'world';
  targetRot: [number, number, number] | null = null;
  targetTrans: [number, number] | null = null;
  isAutoPan = false;

  constructor(private http: HttpClient, private ngZone: NgZone, private cdr: ChangeDetectorRef) {}

  ngOnInit() { this.init(); }

  switchMode(mode: 'flat' | 'globe') {
    if (this.mapMode === mode) return;
    this.mapMode = mode;
    this.selectedContinent = 'world';
    if (this.rafId) cancelAnimationFrame(this.rafId);
    if (this.cachedWorld) {
      this.ngZone.runOutsideAngular(() => this.drawMap(this.cachedWorld));
    }
    this.cdr.detectChanges();
  }

  focusContinent(id: string) {
    this.selectedContinent = id;
    const target = this.continents.find(c => c.id === id);
    if (target) {
      this.targetRot = [...target.rot] as [number, number, number];
      this.targetTrans = [target.tx, target.ty];
      this.isAutoPan = true;
    }
  }

  switchSourceMode(mode: 'traffic' | 'intel') {
    if (this.sourceMode === mode) return;
    this.sourceMode = mode;
    this.loading = true;
    this.selectedCountry = null;
    this.cdr.detectChanges();

    if (mode === 'intel') {
      this.loadThreatIntelMap();
    } else {
      this.loadThreatMap();
    }
  }

  selectCountry(src: AttackSource) {
    this.selectedCountry = this.selectedCountry?.country === src.country ? null : src;
    this.ngZone.run(() => this.cdr.detectChanges());
  }

  tagLabel(tag: string): string {
    const labels: Record<string, string> = {
      'port-scan':            'Port Scan',
      'dns-beaconing':        'DNS Beaconing',
      'dns-tunneling':        'DNS Tunneling',
      'threat-intel':         'Known Malicious',
      'ids-alert':            'Agent-S Alert',
      'volume-anomaly':       'Volume Anomaly',
      'lateral-movement':     'Lateral Movement',
      'credential-stuffing':  'Credential Stuffing',
      'beaconing':            'C2 Beaconing',
      'slow-scan':            'Slow Scan',
      'data-staging':         'Data Staging',
      'internal-recon':       'Internal Recon',
      'new-external-contact': 'New External Contact',
      'icmp-flood':           'ICMP Flood',
      'nxdomain-flood':       'NX Domain Flood',
      'abnormal-hours':       'Abnormal Hours',
      'tls-cert-anomaly':     'TLS Cert Anomaly',
      'protocol-misuse':      'Protocol Misuse',
      'large-volume-exfil':   'Large Exfil',
      'sensitive-country':    'Sensitive Country',
      'sigma':                'Sigma Rule',
      'dga':                  'DGA Domain',
      'doh-evasion':          'DoH Evasion',
      'malicious-domain':     'Malicious Domain',
      'abnormal-rst':         'Abnormal RST',
      'ip-conflict':          'IP Conflict',
    };
    if (labels[tag]) return labels[tag];
    // Sigma / Suricata rule names — strip ET category prefix, replace vendor names
    const clean = tag
      .replace(/^ET\s+(INFO|SCAN|POLICY|ATTACK|MALWARE|TROJAN|EXPLOIT|WEB_SERVER)\s+/i, '')
      .replace(/suricata/gi, 'Agent-S')
      .replace(/zeek/gi, 'Agent-Z');
    return clean.length > 28 ? clean.substring(0, 26) + '…' : clean;
  }

  countryFlag(code: string): string {
    if (!code || code.length !== 2) return '🌍';
    return code.toUpperCase().replace(/./g, c =>
      String.fromCodePoint(127397 + c.charCodeAt(0))
    );
  }

  ngOnDestroy() {
    if (this.rafId) cancelAnimationFrame(this.rafId);
    clearTimeout(this.resizeTimer);
  }

  @HostListener('window:resize')
  onResize() {
    clearTimeout(this.resizeTimer);
    // Debounce: only redraw 300ms after resize stops. Reuse cached data so no
    // extra API call fires — DevTools open/close triggers many resize events.
    this.resizeTimer = setTimeout(() => {
      if (this.rafId) cancelAnimationFrame(this.rafId);
      if (this.cachedWorld) {
        this.ngZone.runOutsideAngular(() => this.drawMap(this.cachedWorld));
      }
    }, 300);
  }

  private async init() {
    const seq = ++this.initSeq;
    if (this.rafId) cancelAnimationFrame(this.rafId);

    const world = await (this.cachedWorld
      ? Promise.resolve(this.cachedWorld)
      : this.http.get('/assets/world-110m.json').toPromise());

    if (seq !== this.initSeq) return;
    this.cachedWorld = world;
    this.loadThreatMap();
  }

  private loadThreatMap() {
    this.http.get<any>('/api/threat-map').subscribe({
      next: (data: any) => this.applyCountryData(data?.countries ?? [], 'traffic'),
      error: () => this.applyCountryData([], 'traffic'),
    });
  }

  private loadThreatIntelMap() {
    this.http.get<any>('/api/threat-intel-map').subscribe({
      next: (data: any) => this.applyCountryData((data?.countries ?? []).map((c: any) => ({
        country: c.country,
        code: c.code,
        lat: c.lat,
        lon: c.lon,
        count: c.hit_count ?? c.ip_count ?? c.count ?? 0,
        attacks: c.attacks ?? [],
      })), 'intel'),
      error: () => this.applyCountryData([], 'intel'),
    });
  }

  private applyCountryData(raw: any[], mode: 'traffic' | 'intel') {
    const normalized = raw.map((c, i) => ({
      ...c,
      count: Number(c.count ?? c.hit_count ?? 0) || 0,
      attacks: c.attacks ?? [],
      color: ARC_COLORS[i % ARC_COLORS.length],
    })).filter((c) => c.country && c.country !== 'Unknown' && c.count > 0)
      .sort((a, b) => (b.count ?? 0) - (a.count ?? 0))
      .slice(0, 15);

    this.attackSources = normalized;
    this.totalAttacks = normalized.reduce((s, c) => s + (c.count ?? 0), 0);
    this.ngZone.run(() => {
      this.loading = false;
      this.cdr.detectChanges();
    });

    if (this.cachedWorld) {
      this.ngZone.runOutsideAngular(() => this.drawMap(this.cachedWorld));
    }
  }

  private drawMap(world: any) {
    this.mapMode === 'globe' ? this.drawGlobe(world) : this.drawFlatMap(world);
  }

  private makeTooltip(el: HTMLElement): {
    show: (x: number, y: number, src: AttackSource) => void;
    hide: () => void;
  } {
    const tip = document.createElement('div');
    tip.className = 'tm-map-tooltip';
    tip.innerHTML = '<span class="tm-tip-flag"></span><span class="tm-tip-country"></span><span class="tm-tip-count"></span>';
    el.appendChild(tip);
    const flag    = tip.querySelector('.tm-tip-flag')!    as HTMLElement;
    const country = tip.querySelector('.tm-tip-country')! as HTMLElement;
    const count   = tip.querySelector('.tm-tip-count')!   as HTMLElement;
    return {
      show: (x, y, src) => {
        flag.textContent    = this.countryFlag(src.code);
        country.textContent = src.country;
        count.textContent   = `${src.count.toLocaleString()} hits`;
        tip.style.left = (x + 14) + 'px';
        tip.style.top  = (y - 18) + 'px';
        tip.classList.add('visible');
      },
      hide: () => tip.classList.remove('visible'),
    };
  }

  private drawFlatMap(world: any) {
    const el = this.mapRef.nativeElement;
    const W  = el.clientWidth  || 900;
    const H  = el.clientHeight || 480;

    d3.select(el).selectAll('*').remove();
    el.style.position = '';

    const svg = d3.select(el).append('svg')
      .attr('width', W).attr('height', H)
      .attr('viewBox', `0 0 ${W} ${H}`)
      .style('display', 'block');

    const defs = svg.append('defs');
    const mkGlow = (id: string, std: number) => {
      const f = defs.append('filter').attr('id', id).attr('x', '-100%').attr('y', '-100%').attr('width', '300%').attr('height', '300%');
      f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', std).attr('result', 'blur');
      f.append('feMerge').selectAll('n').data(['blur', 'SourceGraphic']).enter().append('feMergeNode').attr('in', (d: any) => d);
    };
    mkGlow('f-arc', 3); mkGlow('f-dot', 5); mkGlow('f-green', 7);

    const oceanGrad = defs.append('radialGradient').attr('id', 'f-ocean').attr('cx', '50%').attr('cy', '50%').attr('r', '55%');
    oceanGrad.append('stop').attr('offset', '0%').attr('stop-color', '#021436');
    oceanGrad.append('stop').attr('offset', '100%').attr('stop-color', '#000511');

    const scaleFactor = this.previewMode ? Math.min(W, H * 1.8) / 6.2 : W / 6.2;
    const proj  = d3.geoNaturalEarth1().scale(scaleFactor).translate([W / 2, H / 2]);
    const pathFn = d3.geoPath().projection(proj);

    const mapG = svg.append('g');

    mapG.append('path').datum({ type: 'Sphere' } as any).attr('d', pathFn as any).attr('fill', 'url(#f-ocean)');
    mapG.append('path').datum(d3.geoGraticule().step([20, 20])()).attr('d', pathFn as any)
      .attr('fill', 'none').attr('stroke', 'rgba(14,165,233,0.15)').attr('stroke-width', 0.5);
    const land    = (topojson as any).feature(world, world.objects.countries);
    const borders = (topojson as any).mesh(world, world.objects.countries, (a: any, b: any) => a !== b);
    mapG.selectAll('.land').data((land as any).features).enter().append('path')
      .attr('class', 'land').attr('d', pathFn as any)
      .attr('fill', '#011026')
      .attr('stroke', '#0ea5e9').attr('stroke-width', 0.6);
    mapG.append('path').datum(borders).attr('d', pathFn as any).attr('fill', 'none').attr('stroke', '#0ea5e9').attr('stroke-width', 0.6);
    mapG.append('path').datum({ type: 'Sphere' } as any).attr('d', pathFn as any).attr('fill', 'none').attr('stroke', 'rgba(14,165,233,0.6)').attr('stroke-width', 2);

    const TARGET: [number, number] = [80.0, 12.0];
    const txy = proj(TARGET)!;

    const arcG = mapG.append('g'); const dotG = mapG.append('g'); const partG = mapG.append('g');
    const hoverG = mapG.append('g'); const tG = mapG.append('g');

    const tooltip = this.makeTooltip(el);

    type FlatP = { path: SVGPathElement; el: SVGCircleElement; t: number; speed: number };
    const flatParticles: FlatP[] = [];

    this.attackSources.forEach((src, i) => {
      const sxy = proj([src.lon, src.lat]);
      if (!sxy) return;

      // Arc
      const arcLine = { type: 'LineString', coordinates: [[src.lon, src.lat], TARGET] };
      const arcEl = arcG.append('path').attr('d', pathFn(arcLine as any) || '')
        .attr('fill', 'none').attr('stroke', src.color).attr('stroke-width', 6)
        .attr('stroke-linecap', 'round').attr('opacity', 1).attr('filter', 'url(#f-arc)').node()!;

      // Source dot
      const r = this.sizeForCount(src.count);
      dotG.append('circle').attr('cx', sxy[0]).attr('cy', sxy[1]).attr('r', r + 5)
        .attr('fill', src.color).attr('opacity', 0.15).attr('filter', 'url(#f-dot)');
      dotG.append('circle').attr('cx', sxy[0]).attr('cy', sxy[1]).attr('r', r)
        .attr('fill', src.color).attr('opacity', 0.95).attr('filter', 'url(#f-dot)');
      dotG.append('circle').attr('cx', sxy[0]).attr('cy', sxy[1]).attr('r', Math.max(2, r * 0.4))
        .attr('fill', '#fff').attr('opacity', 0.9);
      const sr = dotG.append('circle').attr('cx', sxy[0]).attr('cy', sxy[1]).attr('r', r).attr('fill', 'none')
        .attr('stroke', src.color).attr('stroke-width', 1.5).attr('opacity', 0);
      this.pulseRing(sr, i * 200, r + 12);

      // Transparent hover hit area
      hoverG.append('circle').attr('cx', sxy[0]).attr('cy', sxy[1]).attr('r', r + 10)
        .attr('fill', 'transparent').attr('cursor', 'pointer')
        .on('mouseenter', (event: MouseEvent) => tooltip.show(sxy[0], sxy[1], src))
        .on('mouseleave', () => tooltip.hide());

      // Particles (3 per arc)
      [0, 0.33, 0.66].forEach(offset => {
        const pEl = partG.append('circle').attr('r', 2.8).attr('fill', src.color).attr('opacity', 0).attr('filter', 'url(#f-dot)').node()!;
        flatParticles.push({ path: arcEl, el: pEl, t: (offset + Math.random() * 0.08) % 1, speed: 0.0022 + Math.random() * 0.0014 });
      });
    });

    // Target beacon
    tG.append('circle').attr('cx', txy[0]).attr('cy', txy[1]).attr('r', 8).attr('fill', '#22c55e').attr('filter', 'url(#f-green)');
    tG.append('circle').attr('cx', txy[0]).attr('cy', txy[1]).attr('r', 3.5).attr('fill', '#fff').attr('opacity', 0.95);
    const tr1 = tG.append('circle').attr('cx', txy[0]).attr('cy', txy[1]).attr('r', 8).attr('fill', 'none').attr('stroke', '#22c55e').attr('stroke-width', 1.8).attr('opacity', 0);
    const tr2 = tG.append('circle').attr('cx', txy[0]).attr('cy', txy[1]).attr('r', 8).attr('fill', 'none').attr('stroke', '#22c55e').attr('stroke-width', 1).attr('opacity', 0);
    this.pulseRing(tr1, 0, 30); this.pulseRing(tr2, 700, 46);

    // ── Zoom & Pan (Flat Map) ─────────────────────────────────────────
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.5, 8])
      .on('start', () => {
        this.isAutoPan = false;
        this.ngZone.run(() => this.selectedContinent = 'world');
        svg.style('cursor', 'grabbing');
      })
      .on('zoom', (event: any) => {
        mapG.attr('transform', event.transform);
        
        // Scale elements
        const k = event.transform.k;
        mapG.selectAll('circle').filter((d: any) => !d).attr('transform', `scale(${1/k})`);
      })
      .on('end', () => { svg.style('cursor', 'grab'); });

    svg.call(zoom as any);

    const frame = () => {
      if (this.isAutoPan && this.targetTrans) {
        const tx = this.targetTrans[0] * W;
        const ty = this.targetTrans[1] * H;
        
        // If we want smooth pan with zoom, we transition the SVG using zoom:
        svg.transition().duration(600).ease(d3.easeCubicOut)
          .call(zoom.transform as any, d3.zoomIdentity.translate(W/2 - tx, H/2 - ty).scale(1.8));
          
        this.isAutoPan = false;
      }

      flatParticles.forEach(p => {
        p.t = (p.t + p.speed) % 1;
        try {
          const len = p.path.getTotalLength();
          const pt  = p.path.getPointAtLength(p.t * len);
          d3.select(p.el).attr('cx', pt.x).attr('cy', pt.y).attr('opacity', 0.9);
        } catch (_) {}
      });
      this.rafId = requestAnimationFrame(frame);
    };
    this.rafId = requestAnimationFrame(frame);
  }

  private drawGlobe(world: any) {
    const el = this.mapRef.nativeElement;
    const W  = el.clientWidth  || 900;
    const H  = el.clientHeight || 480;

    d3.select(el).selectAll('*').remove();
    el.style.position = 'relative';

    // ── Layer 1: canvas for rotating globe base ────────────────
    const canvas = d3.select(el).append('canvas')
      .attr('width', W).attr('height', H)
      .style('position', 'absolute').style('top', '0').style('left', '0')
      .node() as HTMLCanvasElement;
    const ctx = canvas.getContext('2d')!;

    // ── Layer 2: SVG overlay for arcs + particles ──────────────
    const svgEl = d3.select(el).append('svg')
      .attr('width', W).attr('height', H)
      .attr('viewBox', `0 0 ${W} ${H}`)
      .style('position', 'absolute').style('top', '0').style('left', '0')
      .style('pointer-events', 'none');

    const defs = svgEl.append('defs');
    const makeGlow = (id: string, std: number) => {
      const f = defs.append('filter').attr('id', id)
        .attr('x', '-100%').attr('y', '-100%').attr('width', '300%').attr('height', '300%');
      f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', std).attr('result', 'blur');
      f.append('feMerge').selectAll('n').data(['blur', 'SourceGraphic']).enter().append('feMergeNode').attr('in', (d: any) => d);
    };
    makeGlow('g-arc',   3);
    makeGlow('g-dot',   5);
    makeGlow('g-green', 8);

    const R    = Math.min(W, H) * 0.46;
    const rot: [number, number, number] = [0, -20, 0];
    const proj = d3.geoOrthographic().scale(R).translate([W / 2, H / 2]).clipAngle(90).rotate(rot);

    // Canvas path generator (draws to ctx)
    const pCtx = d3.geoPath().projection(proj).context(ctx);
    // SVG path generator (returns d string)
    const pSvg = d3.geoPath().projection(proj);

    const land    = (topojson as any).feature(world, world.objects.countries);
    const borders = (topojson as any).mesh(world, world.objects.countries, (a: any, b: any) => a !== b);
    const grat    = d3.geoGraticule().step([20, 20])();

    // Reusable ocean radial gradient (canvas)
    const oceanGrad = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, R * 1.05);
    oceanGrad.addColorStop(0,   '#021436');
    oceanGrad.addColorStop(0.7, '#010c24');
    oceanGrad.addColorStop(1,   '#000511');

    const TARGET: [number, number] = [80.0, 12.0]; // India — receiving network

    // ── SVG groups (order = painter's algorithm) ───────────────
    const arcG      = svgEl.append('g');
    const srcDotG   = svgEl.append('g');
    const particleG = svgEl.append('g');
    const targetG   = svgEl.append('g');

    // ── Arc paths (one per source, redrawn each frame) ─────────
    const arcs = this.attackSources.map(src => ({
      src:    [src.lon, src.lat] as [number, number],
      color:  src.color,
      pathEl: arcG.append('path')
        .attr('fill', 'none').attr('stroke', src.color)
        .attr('stroke-width', 5.0).attr('stroke-linecap', 'round')
        .attr('opacity', 1).attr('filter', 'url(#g-arc)')
        .node()!,
    }));

    // ── Source country dots ────────────────────────────────────
    const srcDots = this.attackSources.map(src => ({
      coords: [src.lon, src.lat] as [number, number],
      color:  src.color,
      r:      this.sizeForCount(src.count),
      el:     srcDotG.append('circle')
        .attr('r', this.sizeForCount(src.count))
        .attr('fill', src.color).attr('filter', 'url(#g-dot)')
        .node()!,
    }));

    // ── Particles (3 per arc, staggered) ──────────────────────
    const globeParticles = this.attackSources.flatMap(src =>
      [0, 0.33, 0.66].map(offset => ({
        src:   [src.lon, src.lat] as [number, number],
        t:     (offset + Math.random() * 0.08) % 1,
        speed: 0.0022 + Math.random() * 0.0014,
        el:    particleG.append('circle')
          .attr('r', 2.8).attr('fill', src.color).attr('opacity', 0)
          .attr('filter', 'url(#g-dot)').node()!,
      }))
    );

    // ── Target beacon (India) ──────────────────────────────────
    targetG.append('circle').attr('r', 8).attr('fill', '#22c55e').attr('filter', 'url(#g-green)');
    targetG.append('circle').attr('r', 3.5).attr('fill', '#ffffff').attr('opacity', 0.95);
    const ring1 = targetG.append('circle').attr('r', 8).attr('fill', 'none')
      .attr('stroke', '#22c55e').attr('stroke-width', 1.8).attr('opacity', 0);
    const ring2 = targetG.append('circle').attr('r', 8).attr('fill', 'none')
      .attr('stroke', '#22c55e').attr('stroke-width', 1).attr('opacity', 0);
    this.pulseRing(ring1, 0, 30);
    this.pulseRing(ring2, 700, 46);

    // Visibility: is this lonLat on the front hemisphere?
    const frontHemi = (lonLat: [number, number]) =>
      d3.geoDistance(lonLat, [-rot[0], -rot[1]] as [number, number]) < Math.PI / 2;

    // ── Atmosphere glow canvas gradient ───────────────────────
    const atmoGrad = ctx.createRadialGradient(W / 2, H / 2, R * 0.88, W / 2, H / 2, R * 1.22);
    atmoGrad.addColorStop(0, 'rgba(14,165,233,0.3)');
    atmoGrad.addColorStop(1, 'rgba(14,165,233,0)');

    // ── Tooltip ────────────────────────────────────────────────
    const tooltip = this.makeTooltip(el);

    canvas.addEventListener('mousemove', (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      let found: AttackSource | null = null;
      let foundXY: [number, number] | null = null;
      let minD = 28;
      this.attackSources.forEach(src => {
        const xy = proj([src.lon, src.lat]);
        if (!xy || !frontHemi([src.lon, src.lat] as [number, number])) return;
        const d = Math.hypot(mx - xy[0], my - xy[1]);
        if (d < minD) { minD = d; found = src; foundXY = xy as [number, number]; }
      });
      if (found && foundXY) tooltip.show(foundXY[0], foundXY[1], found);
      else tooltip.hide();
    });
    canvas.addEventListener('mouseleave', () => tooltip.hide());

    // ── Drag-to-rotate ─────────────────────────────────────────
    let dragStart: [number, number] | null = null;
    let rotStart: [number, number, number] = [...rot] as [number, number, number];
    let isDragging = false;
    canvas.style.cursor = 'grab';

    d3.select(canvas).call(
      (d3.drag() as any)
        .on('start', (event: any) => {
          dragStart = [event.x, event.y];
          rotStart  = [...rot] as [number, number, number];
          isDragging = true;
          this.isAutoPan = false;
          this.ngZone.run(() => this.selectedContinent = 'world');
          canvas.style.cursor = 'grabbing';
        })
        .on('drag', (event: any) => {
          if (!dragStart) return;
          const sens = 0.35;
          rot[0] = rotStart[0] + (event.x - dragStart[0]) * sens;
          rot[1] = Math.max(-80, Math.min(80, rotStart[1] - (event.y - dragStart[1]) * sens));
          proj.rotate(rot);
        })
        .on('end', () => { dragStart = null; isDragging = false; canvas.style.cursor = 'grab'; })
    );

    // ── Animation loop (auto-rotate + user drag) ───────────
    const frame = () => {
      if (this.isAutoPan && this.targetRot) {
        let diff0 = this.targetRot[0] - rot[0];
        while (diff0 > 180) diff0 -= 360;
        while (diff0 < -180) diff0 += 360;
        rot[0] += diff0 * 0.08;
        let diff1 = this.targetRot[1] - rot[1];
        rot[1] += diff1 * 0.08;
        proj.rotate(rot);
        
        if (Math.abs(diff0) < 0.5 && Math.abs(diff1) < 0.5) {
          this.isAutoPan = false;
        }
      } else if (!isDragging && this.selectedContinent === 'world') {
        rot[0] = (rot[0] + 0.15) % 360;
        proj.rotate(rot);
      }
      // Canvas: atmosphere → ocean → graticule → land → borders → sphere rim
      ctx.clearRect(0, 0, W, H);

      ctx.beginPath(); ctx.arc(W / 2, H / 2, R * 1.22, 0, Math.PI * 2);
      ctx.fillStyle = atmoGrad; ctx.fill();

      ctx.beginPath(); pCtx({ type: 'Sphere' } as any);
      ctx.fillStyle = oceanGrad; ctx.fill();

      ctx.beginPath(); pCtx(grat);
      ctx.strokeStyle = 'rgba(14,165,233,0.15)'; ctx.lineWidth = 0.5; ctx.stroke();

      (land as any).features.forEach((d: any) => {
        ctx.beginPath(); pCtx(d);
        ctx.fillStyle = '#011026';
        ctx.fill();
        ctx.strokeStyle = '#0ea5e9'; ctx.lineWidth = 0.6; ctx.stroke();
      });

      ctx.beginPath(); pCtx(borders as any);
      ctx.strokeStyle = '#0ea5e9'; ctx.lineWidth = 0.6; ctx.stroke();

      ctx.beginPath(); pCtx({ type: 'Sphere' } as any);
      ctx.strokeStyle = 'rgba(14,165,233,0.6)'; ctx.lineWidth = 2.0; ctx.stroke();

      // SVG: redraw arc paths (projection changed)
      arcs.forEach(a => {
        const d = pSvg({ type: 'LineString', coordinates: [a.src, TARGET] } as any);
        d3.select(a.pathEl).attr('d', d || '');
      });

      // SVG: source country dots
      srcDots.forEach(s => {
        const xy  = proj(s.coords);
        const vis = frontHemi(s.coords);
        d3.select(s.el)
          .attr('cx', xy && vis ? xy[0] : -999)
          .attr('cy', xy && vis ? xy[1] : -999)
          .attr('opacity', xy && vis ? 0.95 : 0);
      });

      // SVG: particles — great-circle interpolation
      globeParticles.forEach(p => {
        p.t = (p.t + p.speed) % 1;
        const interp = d3.geoInterpolate(p.src, TARGET);
        const pt = interp(p.t) as [number, number];
        const xy  = proj(pt);
        const vis = frontHemi(pt);
        d3.select(p.el)
          .attr('cx', xy && vis ? xy[0] : -999)
          .attr('cy', xy && vis ? xy[1] : -999)
          .attr('opacity', xy && vis ? 0.9 : 0);
      });

      // SVG: target beacon follows globe rotation
      const txy  = proj(TARGET);
      const tvis = frontHemi(TARGET);
      targetG
        .attr('transform', txy ? `translate(${txy[0]},${txy[1]})` : 'translate(-999,-999)')
        .attr('opacity', tvis ? 1 : 0);

      this.rafId = requestAnimationFrame(frame);
    };

    this.rafId = requestAnimationFrame(frame);
  }


  private pulseRing(sel: any, delay: number, maxR = 18) {
    const startR = Math.max(3, maxR * 0.2);
    const repeat = () => {
      sel.attr('r', startR).attr('opacity', 0.9)
        .transition().delay(delay).duration(1600).ease(d3.easeCubicOut)
        .attr('r', maxR).attr('opacity', 0)
        .on('end', repeat);
      delay = 0; // only delay on first ring
    };
    repeat();
  }

  private sizeForCount(count: number): number {
    return Math.min(12, Math.max(5, Math.log2(count + 1) * 1.6));
  }
}

