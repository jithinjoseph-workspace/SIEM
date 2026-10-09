import {
  Component,
  ElementRef,
  Input,
  Output,
  EventEmitter,
  OnInit,
  OnDestroy,
  OnChanges,
  SimpleChanges,
  NgZone,
  ViewChild,
  HostListener,
  signal,
  computed
} from '@angular/core';
import { CommonModule } from '@angular/common';
import * as THREE from 'three';
import { Agent, Alert } from '../../core/models/siem.models';

interface ThreatArc {
  fromName: string;
  fromIp: string;
  fromLat: number;
  fromLon: number;
  toAgent: string;
  toLat: number;
  toLon: number;
  threatType: string;
  color: number;
  curve: THREE.QuadraticBezierCurve3;
  mesh: THREE.Line;
  pulseMesh: THREE.Mesh;
  progress: number;
  speed: number;
}

interface EndpointBeacon {
  agentId: string;
  name: string;
  ip: string;
  osType: string;
  status: string;
  lat: number;
  lon: number;
  position: THREE.Vector3;
  meshGroup: THREE.Group;
  ringMesh: THREE.Mesh;
}

@Component({
  selector: 'app-cyber-threat-globe',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './cyber-threat-globe.component.html',
  styleUrls: ['./cyber-threat-globe.component.css']
})
export class CyberThreatGlobeComponent implements OnInit, OnDestroy, OnChanges {
  @ViewChild('globeCanvas', { static: true }) canvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('container', { static: true }) containerRef!: ElementRef<HTMLDivElement>;

  @Input() agents: Agent[] = [];
  @Input() alerts: Alert[] = [];
  @Output() inspectAgent = new EventEmitter<string>();

  // Interactive state
  autoRotate = signal<boolean>(true);
  threatArcsVisible = signal<boolean>(true);
  satelliteDefenseVisible = signal<boolean>(true);
  selectedBeacon = signal<EndpointBeacon | null>(null);

  // Live Threat Feed Ticker
  activeThreatCount = signal<number>(4);
  interceptRate = signal<string>('99.4%');
  packetsScanned = signal<string>('184,920/s');
  latestInterceptLog = signal<string>('LIVE: Intercepted SSH Brute Force from 185.220.101.5 -> srv-prod-ubuntu-01 (Netsh Blocked)');

  private scene!: THREE.Scene;
  private camera!: THREE.PerspectiveCamera;
  private renderer!: THREE.WebGLRenderer;
  private animFrameId?: number;

  // 3D Objects
  private globeGroup = new THREE.Group();
  private sphereWireframe!: THREE.Mesh;
  private glowSphere!: THREE.Mesh;
  private continentPoints!: THREE.Points;
  private defenseRingGroup = new THREE.Group();
  private satelliteMesh!: THREE.Group;

  private threatArcs: ThreatArc[] = [];
  private endpointBeacons: EndpointBeacon[] = [];

  // Interaction controls
  private isDragging = false;
  private previousMousePosition = { x: 0, y: 0 };
  private targetRotation = { x: 0.15, y: 0 };
  private currentRotation = { x: 0.15, y: 0 };
  private zoomLevel = 1.0;
  private raycaster = new THREE.Raycaster();
  private mouseVector = new THREE.Vector2();

  constructor(private ngZone: NgZone) {}

  ngOnInit(): void {
    this.initThree();
    this.buildGlobe();
    this.buildContinents();
    this.buildDefenseRings();
    this.rebuildEndpointBeacons();
    this.rebuildThreatArcsFromAlerts();

    this.ngZone.runOutsideAngular(() => {
      this.animate();
    });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (!this.scene) return;

    if (changes['agents'] && this.agents.length > 0) {
      this.rebuildEndpointBeacons();
    }

    if (changes['alerts'] && this.alerts.length > 0) {
      this.rebuildThreatArcsFromAlerts();
    }
  }

  ngOnDestroy(): void {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
    }
    if (this.renderer) {
      this.renderer.dispose();
    }
  }

  private initThree(): void {
    const canvas = this.canvasRef.nativeElement;
    const width = canvas.clientWidth || 800;
    const height = canvas.clientHeight || 460;

    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x060b19, 0.0018);

    this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    this.camera.position.set(0, 0, 23.5);
    this.camera.lookAt(0, 0, 0);

    this.renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Ambient and Point Lights
    const ambientLight = new THREE.AmbientLight(0x0a2540, 1.5);
    this.scene.add(ambientLight);

    const cyanLight = new THREE.PointLight(0x00e5ff, 3.5, 50);
    cyanLight.position.set(15, 20, 15);
    this.scene.add(cyanLight);

    const roseLight = new THREE.PointLight(0xf43f5e, 2.8, 50);
    roseLight.position.set(-15, -10, -15);
    this.scene.add(roseLight);

    this.scene.add(this.globeGroup);
  }

  private latLonToVector3(lat: number, lon: number, radius: number): THREE.Vector3 {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);

    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);

    return new THREE.Vector3(x, y, z);
  }

  private buildGlobe(): void {
    const radius = 7.0;

    // 1. Inner Holographic Core Sphere
    const coreGeo = new THREE.SphereGeometry(radius * 0.98, 36, 36);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x051329,
      transparent: true,
      opacity: 0.88
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    this.globeGroup.add(coreMesh);

    // 2. Wireframe Lat/Lon Grid
    const wireGeo = new THREE.SphereGeometry(radius, 28, 28);
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x00e5ff,
      wireframe: true,
      transparent: true,
      opacity: 0.16
    });
    this.sphereWireframe = new THREE.Mesh(wireGeo, wireMat);
    this.globeGroup.add(this.sphereWireframe);

    // 3. Equator and Prime Meridian Rings
    const ringGeo = new THREE.RingGeometry(radius * 1.01, radius * 1.03, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x00e5ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.4
    });
    const equatorRing = new THREE.Mesh(ringGeo, ringMat);
    equatorRing.rotation.x = Math.PI / 2;
    this.globeGroup.add(equatorRing);

    // 4. Outer Atmospheric Holographic Glow Shell
    const glowGeo = new THREE.SphereGeometry(radius * 1.08, 32, 32);
    const glowMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.08,
      side: THREE.BackSide
    });
    this.glowSphere = new THREE.Mesh(glowGeo, glowMat);
    this.globeGroup.add(this.glowSphere);
  }

  private buildContinents(): void {
    // Generate realistic geographic landmass point cloud
    const radius = 7.05;
    const pointsCount = 2800;
    const positions = new Float32Array(pointsCount * 3);
    const colors = new Float32Array(pointsCount * 3);

    const baseColor = new THREE.Color(0x00e5ff);
    const landColor = new THREE.Color(0x34d399);

    let idx = 0;
    for (let i = 0; i < pointsCount; i++) {
      const phi = Math.acos(1 - 2 * (i + 0.5) / pointsCount);
      const theta = Math.PI * (1 + Math.sqrt(5)) * (i + 0.5);

      const lat = 90 - (phi * 180 / Math.PI);
      const lon = ((theta * 180 / Math.PI) % 360) - 180;

      const isLand = this.isContinentalCoordinate(lat, lon);

      if (isLand || Math.random() < 0.25) {
        const p = this.latLonToVector3(lat, lon, radius);
        positions[idx * 3] = p.x;
        positions[idx * 3 + 1] = p.y;
        positions[idx * 3 + 2] = p.z;

        const c = isLand ? landColor : baseColor;
        colors[idx * 3] = c.r;
        colors[idx * 3 + 1] = c.g;
        colors[idx * 3 + 2] = c.b;
        idx++;
      }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions.subarray(0, idx * 3), 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors.subarray(0, idx * 3), 3));

    const material = new THREE.PointsMaterial({
      size: 0.12,
      vertexColors: true,
      transparent: true,
      opacity: 0.85
    });

    this.continentPoints = new THREE.Points(geometry, material);
    this.globeGroup.add(this.continentPoints);
  }

  private isContinentalCoordinate(lat: number, lon: number): boolean {
    if (lat > 15 && lat < 70 && lon > -160 && lon < -50) return true;
    if (lat > -55 && lat < 12 && lon > -85 && lon < -35) return true;
    if (lat > 35 && lat < 70 && lon > -10 && lon < 45) return true;
    if (lat > -35 && lat < 37 && lon > -18 && lon < 52) return true;
    if (lat > 5 && lat < 75 && lon > 45 && lon < 145) return true;
    if (lat > -45 && lat < -10 && lon > 110 && lon < 155) return true;
    return false;
  }

  private buildDefenseRings(): void {
    const radius = 7.0;

    const ringGeo = new THREE.RingGeometry(radius * 1.35, radius * 1.37, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x6366f1,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.4
    });
    const defenseRing = new THREE.Mesh(ringGeo, ringMat);
    defenseRing.rotation.x = Math.PI / 3;
    defenseRing.rotation.y = Math.PI / 6;
    this.defenseRingGroup.add(defenseRing);

    this.satelliteMesh = new THREE.Group();
    const satBody = new THREE.Mesh(
      new THREE.BoxGeometry(0.35, 0.2, 0.2),
      new THREE.MeshBasicMaterial({ color: 0x00e5ff })
    );
    const satWingL = new THREE.Mesh(
      new THREE.BoxGeometry(0.5, 0.04, 0.3),
      new THREE.MeshBasicMaterial({ color: 0x38bdf8 })
    );
    satWingL.position.x = -0.45;
    const satWingR = satWingL.clone();
    satWingR.position.x = 0.45;

    this.satelliteMesh.add(satBody, satWingL, satWingR);
    this.satelliteMesh.position.set(radius * 1.36, 0, 0);
    this.defenseRingGroup.add(this.satelliteMesh);

    this.scene.add(this.defenseRingGroup);
  }

  private getAgentCoordinates(agent: Agent): { lat: number; lon: number } {
    const id = agent.id;
    const name = (agent.name || '').toLowerCase();
    if (name.includes('dc') || name.includes('ad') || name.includes('win-ad')) {
      return { lat: 38.9, lon: -77.0 }; // Washington DC / US East
    }
    if (name.includes('ubuntu') || name.includes('prod') || name.includes('srv')) {
      return { lat: 50.1, lon: 8.6 }; // Frankfurt EU
    }
    if (name.includes('mac') || name.includes('analyst') || name.includes('sec')) {
      return { lat: 51.5, lon: -0.1 }; // London UK
    }
    if (name.includes('nginx') || name.includes('dmz') || name.includes('web')) {
      return { lat: 1.3, lon: 103.8 }; // Singapore APAC
    }
    if (name.includes('laptop') || name.includes('win-agent') || name.includes('evofox')) {
      return { lat: 19.07, lon: 72.87 }; // Local endpoint / India
    }

    // Deterministic geographic distribution for any other custom agent ID
    let hash = 0;
    for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) & 0xffffffff;
    const lat = ((Math.abs(hash) % 90) - 35);
    const lon = ((Math.abs(hash >> 8) % 360) - 180);
    return { lat, lon };
  }

  private rebuildEndpointBeacons(): void {
    // Clear existing beacons from scene
    this.endpointBeacons.forEach(b => {
      this.globeGroup.remove(b.meshGroup);
    });
    this.endpointBeacons = [];

    const radius = 7.0;
    const agentList: Agent[] = (this.agents && this.agents.length > 0) ? this.agents : [
      { id: '002', name: 'win-ad-dc01', ip: '192.168.10.20', os: 'Windows Server 2022', version: 'v4.14.7-rust', status: 'active', last_keepalive: new Date().toISOString(), os_type: 'windows' },
      { id: '001', name: 'srv-prod-ubuntu-01', ip: '192.168.10.15', os: 'Ubuntu 24.04 LTS', version: 'v4.14.7-rust', status: 'active', last_keepalive: new Date().toISOString(), os_type: 'linux' },
      { id: '003', name: 'sec-analyst-macbook', ip: '192.168.10.105', os: 'macOS Sonoma 14.5', version: 'v4.14.7-rust', status: 'active', last_keepalive: new Date().toISOString(), os_type: 'macos' },
      { id: '004', name: 'dmz-web-nginx', ip: '192.168.1.50', os: 'Debian 12', version: 'v4.14.7-rust', status: 'disconnected', last_keepalive: new Date().toISOString(), os_type: 'linux' }
    ];

    agentList.forEach(ag => {
      const coords = this.getAgentCoordinates(ag);
      const pos = this.latLonToVector3(coords.lat, coords.lon, radius);
      const group = new THREE.Group();
      group.position.copy(pos);
      group.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), pos.clone().normalize());

      // Vertical Laser Beacon Pillar
      const beamGeo = new THREE.CylinderGeometry(0.04, 0.08, 1.2, 8);
      beamGeo.translate(0, 0.6, 0);
      const beamMat = new THREE.MeshBasicMaterial({
        color: ag.status === 'active' ? 0x00e5ff : 0xf43f5e,
        transparent: true,
        opacity: 0.9
      });
      const beam = new THREE.Mesh(beamGeo, beamMat);

      // Top Beacon Crystal
      const crystalGeo = new THREE.OctahedronGeometry(0.18, 0);
      crystalGeo.translate(0, 1.25, 0);
      const crystalMat = new THREE.MeshBasicMaterial({
        color: ag.status === 'active' ? 0x34d399 : 0xf43f5e
      });
      const crystal = new THREE.Mesh(crystalGeo, crystalMat);

      // Pulsing Ground Ring
      const ringGeo = new THREE.RingGeometry(0.15, 0.35, 16);
      ringGeo.rotateX(-Math.PI / 2);
      const ringMat = new THREE.MeshBasicMaterial({
        color: 0x00e5ff,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);

      group.add(beam, crystal, ring);
      this.globeGroup.add(group);

      this.endpointBeacons.push({
        agentId: ag.id,
        name: ag.name,
        ip: ag.ip,
        osType: ag.os_type,
        status: ag.status,
        lat: coords.lat,
        lon: coords.lon,
        position: pos,
        meshGroup: group,
        ringMesh: ring
      });
    });
  }

  private extractIp(log: string): string | null {
    if (!log) return null;
    const match = log.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    return match ? match[1] : null;
  }

  private ipToCoordinates(ip: string): { lat: number; lon: number; country: string } {
    if (!ip) return { lat: 52.3, lon: 4.9, country: 'Europe' };
    if (ip.startsWith('185.')) return { lat: 52.3, lon: 4.9, country: 'Netherlands' };
    if (ip.startsWith('194.') || ip.startsWith('91.')) return { lat: 55.7, lon: 37.6, country: 'Eastern Europe' };
    if (ip.startsWith('218.') || ip.startsWith('112.')) return { lat: 39.9, lon: 116.4, country: 'East Asia' };
    if (ip.startsWith('198.') || ip.startsWith('104.') || ip.startsWith('172.')) return { lat: 37.7, lon: -122.4, country: 'North America' };
    if (ip.startsWith('80.') || ip.startsWith('82.')) return { lat: 48.8, lon: 2.3, country: 'Western Europe' };

    const parts = ip.split('.').map(Number);
    const p0 = parts[0] || 120;
    const p1 = parts[1] || 80;
    const lat = ((p0 * 7) % 100) - 40;
    const lon = ((p1 * 13) % 360) - 180;
    return { lat, lon, country: 'WAN Gateway' };
  }

  private rebuildThreatArcsFromAlerts(): void {
    // Clear old threat arcs
    this.threatArcs.forEach(arc => {
      this.globeGroup.remove(arc.mesh);
      this.globeGroup.remove(arc.pulseMesh);
      arc.mesh.geometry.dispose();
      (arc.mesh.material as THREE.Material).dispose();
      arc.pulseMesh.geometry.dispose();
      (arc.pulseMesh.material as THREE.Material).dispose();
    });
    this.threatArcs = [];

    const radius = 7.0;

    // Use live alerts if available, otherwise fall back to realistic seed attacks
    const alertsToMap = (this.alerts && this.alerts.length > 0) ? this.alerts.slice(0, 8) : [
      {
        id: 'sim-1',
        timestamp: new Date().toISOString(),
        rule: { id: 5712, level: 10, description: 'sshd: Multiple failed login attempts (Brute-Force)', groups: ['sshd'] },
        agent: { id: '001', name: 'srv-prod-ubuntu-01', ip: '192.168.10.15' },
        full_log: 'Failed password for root from 185.220.101.5 port 42812 ssh2',
        decoded: { decoder_name: 'sshd', src_ip: '185.220.101.5' },
        location: '/var/log/auth.log'
      },
      {
        id: 'sim-2',
        timestamp: new Date().toISOString(),
        rule: { id: 60100, level: 14, description: 'powershell: Suspicious base64-encoded execution (Mimikatz)', groups: ['windows'] },
        agent: { id: '002', name: 'win-ad-dc01', ip: '192.168.10.20' },
        full_log: 'powershell.exe -w hidden -enc c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz from 194.26.29.11',
        decoded: { decoder_name: 'windows', src_ip: '194.26.29.11' },
        location: 'Security-EventLog'
      },
      {
        id: 'sim-3',
        timestamp: new Date().toISOString(),
        rule: { id: 5503, level: 12, description: 'syscheck: Critical security configuration file modified (/etc/shadow)', groups: ['syscheck'] },
        agent: { id: '001', name: 'srv-prod-ubuntu-01', ip: '192.168.10.15' },
        full_log: 'File /etc/shadow modified by remote session from 218.92.0.12',
        decoded: { decoder_name: 'syscheck', src_ip: '218.92.0.12' },
        location: 'syscheck'
      },
      {
        id: 'sim-4',
        timestamp: new Date().toISOString(),
        rule: { id: 70010, level: 15, description: 'ransomware: Suspicious file encryption activity detected', groups: ['malware'] },
        agent: { id: '003', name: 'sec-analyst-macbook', ip: '192.168.10.105' },
        full_log: 'Phishing payload execution from 198.51.100.44',
        decoded: { decoder_name: 'edr', src_ip: '198.51.100.44' },
        location: 'Endpoint-EDR'
      }
    ];

    this.activeThreatCount.set(alertsToMap.length);

    if (alertsToMap[0]) {
      const topAlert = alertsToMap[0];
      this.latestInterceptLog.set(
        `LIVE [L${topAlert.rule.level}]: ${topAlert.rule.description} on ${topAlert.agent.name}`
      );
    }

    alertsToMap.forEach((alert, idx) => {
      let toLat = 50.1;
      let toLon = 8.6;
      const targetAgent = (this.agents || []).find(a => a.name === alert.agent.name || a.id === alert.agent.id);
      if (targetAgent) {
        const c = this.getAgentCoordinates(targetAgent);
        toLat = c.lat;
        toLon = c.lon;
      }

      const srcIp = alert.decoded?.src_ip || this.extractIp(alert.full_log) || `185.220.101.${(idx * 19) % 250 + 1}`;
      const originCoords = this.ipToCoordinates(srcIp);

      const color = alert.rule.level >= 12 ? 0xf43f5e : (alert.rule.level >= 8 ? 0xf97316 : 0x00e5ff);

      const p1 = this.latLonToVector3(originCoords.lat, originCoords.lon, radius);
      const p2 = this.latLonToVector3(toLat, toLon, radius);

      const mid = new THREE.Vector3().addVectors(p1, p2).multiplyScalar(0.5);
      const distance = p1.distanceTo(p2);
      const altitude = radius + Math.max(1.8, distance * 0.42);
      mid.normalize().multiplyScalar(altitude);

      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const points = curve.getPoints(50);
      const geometry = new THREE.BufferGeometry().setFromPoints(points);

      const lineMaterial = new THREE.LineBasicMaterial({
        color,
        transparent: true,
        opacity: 0.5
      });
      const lineMesh = new THREE.Line(geometry, lineMaterial);
      this.globeGroup.add(lineMesh);

      const pulseGeo = new THREE.SphereGeometry(0.14, 12, 12);
      const pulseMat = new THREE.MeshBasicMaterial({ color });
      const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
      pulseMesh.position.copy(p1);
      this.globeGroup.add(pulseMesh);

      this.threatArcs.push({
        fromName: `Adversary (${originCoords.country})`,
        fromIp: srcIp,
        fromLat: originCoords.lat,
        fromLon: originCoords.lon,
        toAgent: alert.agent.name,
        toLat,
        toLon,
        threatType: alert.rule.description,
        color,
        curve,
        mesh: lineMesh,
        pulseMesh,
        progress: (idx * 0.22) % 1.0,
        speed: 0.005 + (idx * 0.001)
      });
    });
  }

  private animate(): void {
    this.animFrameId = requestAnimationFrame(() => this.animate());

    if (this.autoRotate() && !this.isDragging) {
      this.targetRotation.y += 0.0018;
    }

    this.currentRotation.x += (this.targetRotation.x - this.currentRotation.x) * 0.08;
    this.currentRotation.y += (this.targetRotation.y - this.currentRotation.y) * 0.08;

    this.globeGroup.rotation.x = this.currentRotation.x;
    this.globeGroup.rotation.y = this.currentRotation.y;

    if (this.defenseRingGroup) {
      this.defenseRingGroup.rotation.z += 0.003;
      if (this.satelliteMesh) {
        this.satelliteMesh.rotation.y += 0.02;
      }
    }

    const time = performance.now() * 0.002;
    this.threatArcs.forEach(arc => {
      arc.progress += arc.speed;
      if (arc.progress > 1.0) {
        arc.progress = 0;
      }

      if (this.threatArcsVisible()) {
        const point = arc.curve.getPoint(arc.progress);
        arc.pulseMesh.position.copy(point);
        arc.mesh.visible = true;
        arc.pulseMesh.visible = true;
      } else {
        arc.mesh.visible = false;
        arc.pulseMesh.visible = false;
      }
    });

    this.endpointBeacons.forEach(b => {
      const scale = 1.0 + Math.sin(time * 3 + parseFloat(b.agentId)) * 0.25;
      b.ringMesh.scale.set(scale, scale, scale);
    });

    this.renderer.render(this.scene, this.camera);
  }

  onMouseDown(event: MouseEvent): void {
    this.isDragging = true;
    this.previousMousePosition = { x: event.clientX, y: event.clientY };
  }

  onMouseMove(event: MouseEvent): void {
    if (!this.isDragging) return;

    const deltaX = event.clientX - this.previousMousePosition.x;
    const deltaY = event.clientY - this.previousMousePosition.y;

    this.targetRotation.y += deltaX * 0.005;
    this.targetRotation.x += deltaY * 0.005;
    this.targetRotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, this.targetRotation.x));

    this.previousMousePosition = { x: event.clientX, y: event.clientY };
  }

  onMouseUp(): void {
    this.isDragging = false;
  }

  onWheel(event: WheelEvent): void {
    event.preventDefault();
    const zoomDelta = event.deltaY * 0.01;
    this.camera.position.z = Math.max(12, Math.min(35, this.camera.position.z + zoomDelta));
  }

  onCanvasClick(event: MouseEvent): void {
    const rect = this.canvasRef.nativeElement.getBoundingClientRect();
    this.mouseVector.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    this.mouseVector.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    this.raycaster.setFromCamera(this.mouseVector, this.camera);

    const meshesToTest: THREE.Object3D[] = [];
    this.endpointBeacons.forEach(b => {
      meshesToTest.push(...b.meshGroup.children);
    });

    const intersects = this.raycaster.intersectObjects(meshesToTest, false);
    if (intersects.length > 0) {
      const hit = intersects[0].object;
      const beacon = this.endpointBeacons.find(b => b.meshGroup.children.includes(hit as THREE.Mesh));
      if (beacon) {
        this.selectedBeacon.set(beacon);
      }
    }
  }

  toggleAutoRotate(): void {
    this.autoRotate.update(v => !v);
  }

  toggleThreatArcs(): void {
    this.threatArcsVisible.update(v => !v);
  }

  resetCamera(): void {
    this.targetRotation = { x: 0.15, y: 0 };
    this.camera.position.set(0, 0, 23.5);
    this.camera.lookAt(0, 0, 0);
    this.selectedBeacon.set(null);
  }

  triggerInspect(agentId: string): void {
    this.inspectAgent.emit(agentId);
  }

  closeBeaconDossier(): void {
    this.selectedBeacon.set(null);
  }

  @HostListener('window:resize')
  onResize(): void {
    if (!this.renderer || !this.camera) return;
    const canvas = this.canvasRef.nativeElement;
    const width = canvas.clientWidth || 800;
    const height = canvas.clientHeight || 460;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }
}
