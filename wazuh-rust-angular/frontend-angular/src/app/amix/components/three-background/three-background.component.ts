import {
  Component,
  ElementRef,
  Input,
  OnInit,
  OnDestroy,
  OnChanges,
  SimpleChanges,
  ViewChild,
  NgZone,
  HostListener
} from '@angular/core';
import * as THREE from 'three';

interface CabinetConfig {
  title: string;
  subtitle: string;
  icon: string;
  color: number;
  hexStr: string;
  x: number;
  z: number;
  rotationY: number;
}

@Component({
  selector: 'app-three-background',
  standalone: true,
  template: `
    <canvas #canvas class="three-canvas" [class.hidden]="!is3dEnabled"></canvas>
  `,
  styleUrls: ['./three-background.component.css']
})
export class ThreeBackgroundComponent implements OnInit, OnDestroy, OnChanges {
  @ViewChild('canvas', { static: true }) canvasRef!: ElementRef<HTMLCanvasElement>;
  @Input() is3dEnabled: boolean = true;
  @Input() galleryProgress: number = 0; // 0.0 to 1.0 driving camera flight down highway

  private scene!: THREE.Scene;
  private camera!: THREE.PerspectiveCamera;
  private renderer!: THREE.WebGLRenderer;
  private animId?: number;

  // Scene lights
  private cameraLight!: THREE.PointLight;
  private cameraDirLight!: THREE.DirectionalLight;

  // Scene objects
  private gridHelper?: THREE.GridHelper;
  private pillars: THREE.Mesh[] = [];
  private floatingCubes: THREE.Mesh[] = [];
  private starSystem?: THREE.Points;
  private cityBuildings: THREE.Mesh[] = [];
  private arcadeCabinets: THREE.Group[] = [];

  // Animated canvas textures for CRT screens
  private screenCanvases: {
    canvas: HTMLCanvasElement;
    texture: THREE.CanvasTexture;
    color: string;
    icon: string;
    title: string;
    subtitle: string;
  }[] = [];

  // Scroll tracking
  private currentProgress = 0;
  private targetProgress = 0;
  private clock = new THREE.Clock();

  constructor(private ngZone: NgZone) {}

  ngOnInit(): void {
    if (this.is3dEnabled) {
      this.initThree();
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['is3dEnabled']) {
      if (this.is3dEnabled) {
        if (!this.renderer) {
          this.initThree();
        } else {
          this.resumeRenderLoop();
        }
      } else {
        this.pauseRenderLoop();
      }
    }

    if (changes['galleryProgress']) {
      this.targetProgress = Math.min(Math.max(this.galleryProgress, 0), 1);
    }
  }

  ngOnDestroy(): void {
    this.disposeThree();
  }

  @HostListener('window:resize')
  onResize(): void {
    if (!this.renderer || !this.camera) return;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }

  private initThree(): void {
    const canvas = this.canvasRef.nativeElement;
    const width = window.innerWidth;
    const height = window.innerHeight;
    const isMobile = width < 768;

    // 1. Scene & Cyber Atmosphere
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x040612);
    this.scene.fog = new THREE.FogExp2(0x040612, 0.0055);

    // 2. Perspective Camera (tuned FOV 48 for comfortable, complete cabinet framing with generous headroom)
    this.camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 1400);
    this.camera.position.set(-1.2, 4.6, 23.0);
    this.camera.lookAt(2.5, 4.4, 0);

    // 3. WebGL Renderer with ACES Tone Mapping
    this.renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      powerPreference: 'high-performance',
      alpha: false
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.35;

    // 4. Vibrant Lighting (Guarantees machines are never flat black!)
    const ambientLight = new THREE.AmbientLight(0x283858, 2.2);
    this.scene.add(ambientLight);

    const mainSun = new THREE.DirectionalLight(0x88ccff, 1.8);
    mainSun.position.set(30, 80, 40);
    this.scene.add(mainSun);

    const backRim = new THREE.DirectionalLight(0xff007f, 1.4);
    backRim.position.set(-30, 40, -100);
    this.scene.add(backRim);

    // Camera Headlight: travels with camera to illuminate the active machine directly
    this.cameraLight = new THREE.PointLight(0xffffff, 3.2, 45);
    this.scene.add(this.cameraLight);

    this.cameraDirLight = new THREE.DirectionalLight(0xffffff, 1.2);
    this.scene.add(this.cameraDirLight);

    // 5. Extended Tron Neon Grid Floor
    this.createExtendedGrid();

    // 6. Highway Neon Guard Pillars
    this.createHighwayPillars();

    // 7. Cyber City Skyline
    this.createCitySkyline(isMobile);

    // 8. 3D Arcade Cabinets (Heroic, Bright, High-Res Animated CRT Screens)
    this.createArcadeCabinets();

    // 9. Floating Cubes & Starfield
    this.createFloatingCubes(isMobile);
    this.createStarfield(isMobile);

    // 10. Run Animation Loop Outside Angular
    this.ngZone.runOutsideAngular(() => {
      this.animate();
    });
  }

  private createExtendedGrid(): void {
    const size = 700;
    const divisions = 175;
    const grid1 = new THREE.GridHelper(size, divisions, 0x00f0ff, 0x003366);
    grid1.position.set(0, -0.4, -180);
    (grid1.material as THREE.Material).transparent = true;
    (grid1.material as THREE.Material).opacity = 0.65;
    this.scene.add(grid1);

    const grid2 = new THREE.GridHelper(size, divisions / 2, 0xff007f, 0x330033);
    grid2.position.set(0, -0.42, -180);
    (grid2.material as THREE.Material).transparent = true;
    (grid2.material as THREE.Material).opacity = 0.35;
    this.scene.add(grid2);

    this.gridHelper = grid1;
  }

  private createHighwayPillars(): void {
    const colors = [0xff007f, 0x00f0ff, 0xff7700, 0xa855f7, 0x00ff66, 0x00d4ff];
    let colorIdx = 0;

    for (let z = 30; z >= -360; z -= 35) {
      const col = colors[colorIdx % colors.length];
      colorIdx++;
      this.addPillar(-24, z, col);
      this.addPillar(24, z, col);
    }
  }

  private addPillar(x: number, z: number, color: number): void {
    const height = 45;
    const geo = new THREE.CylinderGeometry(0.35, 0.45, height, 12);
    const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9 });
    const pillar = new THREE.Mesh(geo, mat);
    pillar.position.set(x, height / 2 - 0.4, z);

    const glowGeo = new THREE.CylinderGeometry(0.8, 1.0, height, 10);
    const glowMat = new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.18,
      side: THREE.BackSide
    });
    const glow = new THREE.Mesh(glowGeo, glowMat);
    pillar.add(glow);

    this.scene.add(pillar);
    this.pillars.push(pillar);
  }

  private createCitySkyline(isMobile: boolean): void {
    const count = isMobile ? 24 : 50;
    const buildingMat = new THREE.MeshLambertMaterial({ color: 0x080f22 });
    const beaconMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff });

    for (let i = 0; i < count; i++) {
      const w = 7 + Math.random() * 12;
      const d = 7 + Math.random() * 12;
      const h = 30 + Math.random() * 75;

      const side = Math.random() > 0.5 ? 1 : -1;
      const x = side * (50 + Math.random() * 90);
      const z = -20 - Math.random() * 380;

      const geo = new THREE.BoxGeometry(w, h, d);
      const mesh = new THREE.Mesh(geo, buildingMat);
      mesh.position.set(x, h / 2 - 1, z);
      this.scene.add(mesh);
      this.cityBuildings.push(mesh);

      if (h > 55) {
        const beacon = new THREE.Mesh(new THREE.SphereGeometry(0.8, 8, 8), beaconMat);
        beacon.position.set(x, h + 0.6, z);
        this.scene.add(beacon);
      }
    }
  }

  private createArcadeCabinets(): void {
    const cabinetConfigs: CabinetConfig[] = [
      {
        title: 'SHADOW KILL',
        subtitle: 'RANSOMWARE INTERCEPT',
        icon: 'SEC-01',
        color: 0xff0055,
        hexStr: '#ff0055',
        x: 6.2,
        z: 0,
        rotationY: -0.22
      },
      {
        title: 'APT HUNTER',
        subtitle: 'ZERO-DAY PURGE',
        icon: 'APT-02',
        color: 0x00f0ff,
        hexStr: '#00f0ff',
        x: -6.2,
        z: -55,
        rotationY: 0.22
      },
      {
        title: 'FIM SENTINEL',
        subtitle: 'CIPHER CORE',
        icon: 'FIM-03',
        color: 0xff7700,
        hexStr: '#ff7700',
        x: 6.2,
        z: -110,
        rotationY: -0.22
      },
      {
        title: 'NEURAL 120B',
        subtitle: 'SOC COPILOT',
        icon: 'AI-120B',
        color: 0xa855f7,
        hexStr: '#a855f7',
        x: -6.2,
        z: -165,
        rotationY: 0.22
      },
      {
        title: 'ATTACK SIM',
        subtitle: 'RED TEAM MATRIX',
        icon: 'SIM-05',
        color: 0x00ff66,
        hexStr: '#00ff66',
        x: 6.2,
        z: -220,
        rotationY: -0.22
      },
      {
        title: 'TOKIO MESH',
        subtitle: 'HYPERSCALE XDR',
        icon: 'MESH-06',
        color: 0x00d4ff,
        hexStr: '#00d4ff',
        x: -6.2,
        z: -275,
        rotationY: 0.22
      }
    ];

    cabinetConfigs.forEach((cfg) => {
      const cabinetGroup = this.buildHeroicCabinet(cfg);
      this.scene.add(cabinetGroup);
      this.arcadeCabinets.push(cabinetGroup);
    });
  }

  private buildHeroicCabinet(cfg: CabinetConfig): THREE.Group {
    const group = new THREE.Group();
    group.position.set(cfg.x, 0, cfg.z);
    group.rotation.y = cfg.rotationY;

    // Body Material: Sleek cyber cabinet with visible edges and specular sheen
    const bodyMat = new THREE.MeshStandardMaterial({
      color: 0x162035, // Deep navy cyber metal with visible bevels
      roughness: 0.35,
      metalness: 0.7
    });

    const sidePanelMat = new THREE.MeshStandardMaterial({
      color: 0x0f1728,
      roughness: 0.35,
      metalness: 0.8
    });

    const neonMat = new THREE.MeshBasicMaterial({ color: cfg.color });

    // 1. Lower Base Pedestal (W: 5.4, H: 2.9, D: 4.0) - grounded securely
    const baseMesh = new THREE.Mesh(new THREE.BoxGeometry(5.4, 2.9, 4.0), bodyMat);
    baseMesh.position.y = 1.45;
    group.add(baseMesh);

    // 2. Mid Section / Screen Chamber (W: 5.4, H: 3.8, D: 3.6)
    const midMesh = new THREE.Mesh(new THREE.BoxGeometry(5.4, 3.8, 3.6), bodyMat);
    midMesh.position.set(0, 4.8, -0.2);
    group.add(midMesh);

    // 3. Slanted Side Wings (H: 8.2)
    const wingGeo = new THREE.BoxGeometry(0.22, 8.2, 4.2);
    const leftWing = new THREE.Mesh(wingGeo, sidePanelMat);
    leftWing.position.set(-2.81, 4.1, 0.1);
    group.add(leftWing);

    const rightWing = new THREE.Mesh(wingGeo, sidePanelMat);
    rightWing.position.set(2.81, 4.1, 0.1);
    group.add(rightWing);

    // Glowing Neon Side Stripes
    const stripeGeo = new THREE.BoxGeometry(0.08, 8.0, 0.1);
    const leftStripe = new THREE.Mesh(stripeGeo, neonMat);
    leftStripe.position.set(-2.93, 4.1, 2.18);
    group.add(leftStripe);

    const rightStripe = new THREE.Mesh(stripeGeo, neonMat);
    rightStripe.position.set(2.93, 4.1, 2.18);
    group.add(rightStripe);

    // 4. Top Canopy / Marquee Housing (W: 5.4, H: 1.4, D: 4.0)
    const topMesh = new THREE.Mesh(new THREE.BoxGeometry(5.4, 1.4, 4.0), bodyMat);
    topMesh.position.set(0, 7.4, 0.1);
    group.add(topMesh);

    // 5. Bright Self-Lit Neon Marquee Sign (1024x260 HD Canvas Texture) - Fully In Frame
    const marqueeCanvas = this.createMarqueeCanvas(cfg.title, cfg.color);
    const marqueeTex = new THREE.CanvasTexture(marqueeCanvas);
    const marqueeMat = new THREE.MeshBasicMaterial({ map: marqueeTex });
    const marqueeMesh = new THREE.Mesh(new THREE.PlaneGeometry(4.8, 1.15), marqueeMat);
    marqueeMesh.position.set(0, 7.4, 2.12);
    group.add(marqueeMesh);

    // 6. Ultra-Vibrant High-Clarity CRT Screen (Screen spans y = 3.75 to y = 6.55)
    const { canvas: screenCanvas, texture: screenTex } = this.createScreenCanvas(cfg.title, cfg.subtitle, cfg.icon, cfg.color);
    const screenMat = new THREE.MeshBasicMaterial({ map: screenTex });
    const screenMesh = new THREE.Mesh(new THREE.PlaneGeometry(4.5, 2.8), screenMat);
    screenMesh.position.set(0, 5.15, 1.68);
    screenMesh.rotation.x = -0.12; // Authentic backward arcade tilt
    group.add(screenMesh);

    // Keep screen texture reference for live radar pulse
    this.screenCanvases.push({
      canvas: screenCanvas,
      texture: screenTex,
      color: cfg.hexStr,
      icon: cfg.icon,
      title: cfg.title,
      subtitle: cfg.subtitle
    });

    // 7. Control Panel Deck (Grounded at y = 2.85, top surface y = 3.05 - well below screen bottom y = 3.75!)
    const deckMat = new THREE.MeshStandardMaterial({ color: 0x090f1d, roughness: 0.3, metalness: 0.9 });
    const deckMesh = new THREE.Mesh(new THREE.BoxGeometry(5.4, 0.4, 1.6), deckMat);
    deckMesh.position.set(0, 2.85, 2.05);
    deckMesh.rotation.x = 0.10;
    group.add(deckMesh);

    // Control Deck Glowing Buttons (y = 3.12)
    const btnMatA = new THREE.MeshBasicMaterial({ color: cfg.color });
    const btnMatB = new THREE.MeshBasicMaterial({ color: 0x00f0ff });
    const btnMatC = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const btnGeo = new THREE.CylinderGeometry(0.15, 0.15, 0.12, 12);

    const b1 = new THREE.Mesh(btnGeo, btnMatA);
    b1.position.set(0.9, 3.12, 2.2);
    group.add(b1);

    const b2 = new THREE.Mesh(btnGeo, btnMatB);
    b2.position.set(1.4, 3.08, 2.05);
    group.add(b2);

    const b3 = new THREE.Mesh(btnGeo, btnMatC);
    b3.position.set(1.15, 3.14, 2.45);
    group.add(b3);

    // Dual Arcade Joysticks (Low profile, max height y = 3.52, a generous 0.23 gap below screen bottom y = 3.75!)
    const stickMat = new THREE.MeshStandardMaterial({ color: 0xdddddd, metalness: 0.95, roughness: 0.15 });

    // Player 1 Joystick
    const stick1 = new THREE.Mesh(new THREE.CylinderGeometry(0.045, 0.045, 0.28, 8), stickMat);
    stick1.position.set(-1.1, 3.22, 2.15);
    group.add(stick1);

    const ball1 = new THREE.Mesh(new THREE.SphereGeometry(0.16, 12, 12), btnMatA);
    ball1.position.set(-1.1, 3.38, 2.15);
    group.add(ball1);

    // Player 2 Joystick
    const stick2 = new THREE.Mesh(new THREE.CylinderGeometry(0.045, 0.045, 0.28, 8), stickMat);
    stick2.position.set(-0.35, 3.22, 2.15);
    group.add(stick2);

    const ball2 = new THREE.Mesh(new THREE.SphereGeometry(0.16, 12, 12), btnMatB);
    ball2.position.set(-0.35, 3.38, 2.15);
    group.add(ball2);

    // 8. Glowing Neon Framing Tubes
    const tubeGeoV = new THREE.CylinderGeometry(0.08, 0.08, 8.2, 8);
    const leftNeon = new THREE.Mesh(tubeGeoV, neonMat);
    leftNeon.position.set(-2.72, 4.1, 1.95);
    group.add(leftNeon);

    const rightNeon = new THREE.Mesh(tubeGeoV, neonMat);
    rightNeon.position.set(2.72, 4.1, 1.95);
    group.add(rightNeon);

    const tubeGeoH = new THREE.CylinderGeometry(0.08, 0.08, 5.44, 8);
    const topNeon = new THREE.Mesh(tubeGeoH, neonMat);
    topNeon.rotation.z = Math.PI / 2;
    topNeon.position.set(0, 8.12, 1.95);
    group.add(topNeon);

    const underDeckNeon = new THREE.Mesh(tubeGeoH, neonMat);
    underDeckNeon.rotation.z = Math.PI / 2;
    underDeckNeon.position.set(0, 2.62, 2.7);
    group.add(underDeckNeon);

    // 9. Illuminated Coin Door
    const coinDoorMat = new THREE.MeshStandardMaterial({ color: 0x060a14, roughness: 0.5, metalness: 0.7 });
    const coinDoor = new THREE.Mesh(new THREE.BoxGeometry(1.7, 1.8, 0.15), coinDoorMat);
    coinDoor.position.set(0, 1.35, 1.95);
    group.add(coinDoor);

    const coinSlotMat = new THREE.MeshBasicMaterial({ color: 0xff4400 });
    const slot1 = new THREE.Mesh(new THREE.BoxGeometry(0.32, 0.5, 0.1), coinSlotMat);
    slot1.position.set(-0.42, 1.45, 2.05);
    group.add(slot1);

    const slot2 = new THREE.Mesh(new THREE.BoxGeometry(0.32, 0.5, 0.1), coinSlotMat);
    slot2.position.set(0.42, 1.45, 2.05);
    group.add(slot2);

    // 10. Dedicated Key Light & Floor Glow
    const frontLight = new THREE.PointLight(cfg.color, 4.5, 22);
    frontLight.position.set(0, 5.2, 5.0);
    group.add(frontLight);

    const floorLight = new THREE.PointLight(cfg.color, 3.2, 15);
    floorLight.position.set(0, 0.5, 2.2);
    group.add(floorLight);

    return group;
  }

  private createMarqueeCanvas(title: string, colorHex: number): HTMLCanvasElement {
    const canvas = document.createElement('canvas');
    canvas.width = 1024;
    canvas.height = 260;
    const ctx = canvas.getContext('2d')!;
    const hexStr = '#' + colorHex.toString(16).padStart(6, '0');

    // Deep high-contrast cyber background
    ctx.fillStyle = '#060b1a';
    ctx.fillRect(0, 0, 1024, 260);

    // Double Glowing Border
    ctx.strokeStyle = hexStr;
    ctx.lineWidth = 14;
    ctx.strokeRect(12, 12, 1000, 236);

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.75)';
    ctx.lineWidth = 4;
    ctx.strokeRect(24, 24, 976, 212);

    // Bold Futuristic Marquee Typography
    ctx.shadowColor = hexStr;
    ctx.shadowBlur = 32;
    ctx.fillStyle = '#ffffff';
    ctx.font = '900 82px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(title.toUpperCase(), 512, 130);

    ctx.shadowBlur = 18;
    ctx.fillStyle = hexStr;
    ctx.fillText(title.toUpperCase(), 512, 130);

    return canvas;
  }

  private createScreenCanvas(title: string, subtitle: string, icon: string, colorHex: number): { canvas: HTMLCanvasElement; texture: THREE.CanvasTexture } {
    const canvas = document.createElement('canvas');
    canvas.width = 1024;
    canvas.height = 720;
    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    texture.magFilter = THREE.LinearFilter;
    return { canvas, texture };
  }

  private updateScreenTexture(item: {
    canvas: HTMLCanvasElement;
    texture: THREE.CanvasTexture;
    color: string;
    icon: string;
    title: string;
    subtitle: string;
  }, time: number): void {
    const ctx = item.canvas.getContext('2d')!;
    const w = item.canvas.width;
    const h = item.canvas.height;

    // 1. Deep Midnight Blue Cyber CRT Background
    ctx.fillStyle = '#020512';
    ctx.fillRect(0, 0, w, h);

    // 2. High-Tech Cyan Cyber Grid
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.14)';
    ctx.lineWidth = 1.5;
    for (let x = 0; x < w; x += 48) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }

    // 3. Top HUD Status Bar (y = 16..68)
    ctx.fillStyle = 'rgba(6, 12, 28, 0.94)';
    ctx.fillRect(24, 16, w - 48, 52);
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 2.5;
    ctx.strokeRect(24, 16, w - 48, 52);

    // Status light indicator
    ctx.fillStyle = '#00ff88';
    ctx.beginPath();
    ctx.arc(46, 42, 7, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = '#00f0ff';
    ctx.font = '800 21px monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText('LIVE DEFENSE ENGINE // ONLINE', 64, 42);

    ctx.textAlign = 'right';
    ctx.fillStyle = '#00ff88';
    ctx.fillText('SLA: <0.4ms [ACTIVE]', w - 44, 42);

    // 4. Primary Hero Title & Subtitle Card (y = 86..210) - UPPER SECTION (100% CLEAR OF JOYSTICKS!)
    ctx.fillStyle = 'rgba(4, 10, 26, 0.95)';
    ctx.fillRect(36, 86, w - 72, 120);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.28)';
    ctx.lineWidth = 2;
    ctx.strokeRect(36, 86, w - 72, 120);

    // Glowing vertical side bars
    ctx.fillStyle = item.color;
    ctx.fillRect(36, 86, 8, 120);
    ctx.fillRect(w - 44, 86, 8, 120);

    // Main Title: High-contrast, crystal-clear white with neon glow
    ctx.shadowColor = item.color;
    ctx.shadowBlur = 24;
    ctx.fillStyle = '#ffffff';
    ctx.font = '900 52px "Segoe UI", sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(item.title, w / 2, 130);

    // Subtitle in glowing neon
    ctx.shadowBlur = 12;
    ctx.fillStyle = item.color;
    ctx.font = '800 22px monospace';
    ctx.fillText('// ' + item.subtitle, w / 2, 178);
    ctx.shadowBlur = 0;

    // 5. Center Radar & Threat Visualizer (cy = 370)
    const cx = w / 2;
    const cy = 370;
    const pulse1 = 70 + Math.sin(time * 3.5) * 12;
    const pulse2 = 125 + Math.sin(time * 2.2) * 16;
    const pulse3 = (time * 85) % 150;

    // Outer radar ring
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 3.5;
    ctx.beginPath(); ctx.arc(cx, cy, 145, 0, Math.PI * 2); ctx.stroke();

    // Concentric range rings
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
    ctx.lineWidth = 1.8;
    ctx.beginPath(); ctx.arc(cx, cy, pulse1, 0, Math.PI * 2); ctx.stroke();
    ctx.beginPath(); ctx.arc(cx, cy, pulse2, 0, Math.PI * 2); ctx.stroke();

    // Sonar wave ping
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 2.5;
    ctx.beginPath(); ctx.arc(cx, cy, pulse3, 0, Math.PI * 2); ctx.stroke();

    // Radar crosshairs
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.35)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(cx - 145, cy); ctx.lineTo(cx + 145, cy);
    ctx.moveTo(cx, cy - 145); ctx.lineTo(cx, cy + 145);
    ctx.stroke();

    // Rotating radar sweep line
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(time * 3.6) * 145, cy + Math.sin(time * 3.6) * 145);
    ctx.stroke();

    // Center Tactical Node Badge
    ctx.font = '800 28px monospace';
    ctx.fillStyle = item.color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(item.icon, cx, cy);

    // Target lock brackets around threat icon
    const bSize = 56;
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 3;
    // Top-left
    ctx.beginPath();
    ctx.moveTo(cx - bSize, cy - bSize + 16); ctx.lineTo(cx - bSize, cy - bSize); ctx.lineTo(cx - bSize + 16, cy - bSize);
    ctx.stroke();
    // Top-right
    ctx.beginPath();
    ctx.moveTo(cx + bSize, cy - bSize + 16); ctx.lineTo(cx + bSize, cy - bSize); ctx.lineTo(cx + bSize - 16, cy - bSize);
    ctx.stroke();
    // Bottom-left
    ctx.beginPath();
    ctx.moveTo(cx - bSize, cy + bSize - 16); ctx.lineTo(cx - bSize, cy + bSize); ctx.lineTo(cx - bSize + 16, cy + bSize);
    ctx.stroke();
    // Bottom-right
    ctx.beginPath();
    ctx.moveTo(cx + bSize, cy + bSize - 16); ctx.lineTo(cx + bSize, cy + bSize); ctx.lineTo(cx + bSize - 16, cy + bSize);
    ctx.stroke();

    // Target lock label
    ctx.fillStyle = '#00ff88';
    ctx.font = '800 16px monospace';
    ctx.fillText('[ TARGET LOCKED & MONITORED ]', cx, cy + bSize + 22);

    // 6. Lower Telemetry HUD Cards (y = 560..680)
    const cardW = 280;
    const cardH = 88;
    const cardY = 565;

    // Card 1: INGESTION SLA
    ctx.fillStyle = 'rgba(6, 14, 32, 0.9)';
    ctx.fillRect(48, cardY, cardW, cardH);
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.3)';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(48, cardY, cardW, cardH);

    ctx.fillStyle = '#88a0c8';
    ctx.font = '700 15px monospace';
    ctx.textAlign = 'left';
    ctx.fillText('INGESTION SLA', 64, cardY + 28);
    ctx.fillStyle = '#00f0ff';
    ctx.font = '900 24px monospace';
    ctx.fillText('< 0.4 ms', 64, cardY + 62);

    // Card 2: MITRE TACTIC
    ctx.fillStyle = 'rgba(6, 14, 32, 0.9)';
    ctx.fillRect(w / 2 - cardW / 2, cardY, cardW, cardH);
    ctx.strokeStyle = 'rgba(0, 255, 136, 0.3)';
    ctx.strokeRect(w / 2 - cardW / 2, cardY, cardW, cardH);

    ctx.fillStyle = '#88a0c8';
    ctx.font = '700 15px monospace';
    ctx.fillText('MITRE STATUS', w / 2 - cardW / 2 + 16, cardY + 28);
    ctx.fillStyle = '#00ff88';
    ctx.font = '900 24px monospace';
    ctx.fillText('T1486 INTERCEPT', w / 2 - cardW / 2 + 16, cardY + 62);

    // Card 3: INTEGRITY HOOK
    ctx.fillStyle = 'rgba(6, 14, 32, 0.9)';
    ctx.fillRect(w - 48 - cardW, cardY, cardW, cardH);
    ctx.strokeStyle = 'rgba(255, 0, 85, 0.3)';
    ctx.strokeRect(w - 48 - cardW, cardY, cardW, cardH);

    ctx.fillStyle = '#88a0c8';
    ctx.font = '700 15px monospace';
    ctx.fillText('KERNEL HOOK', w - 48 - cardW + 16, cardY + 28);
    ctx.fillStyle = item.color;
    ctx.font = '900 24px monospace';
    ctx.fillText('ACTIVE // RUST', w - 48 - cardW + 16, cardY + 62);

    // 7. Subtle CRT Vignette at Outer Borders (Leaves all text 100% crisp!)
    const vignette = ctx.createRadialGradient(w / 2, h / 2, 300, w / 2, h / 2, 540);
    vignette.addColorStop(0, 'rgba(0, 0, 0, 0)');
    vignette.addColorStop(1, 'rgba(0, 4, 16, 0.42)');
    ctx.fillStyle = vignette;
    ctx.fillRect(0, 0, w, h);

    // CRT Bezel Frame
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 6;
    ctx.strokeRect(3, 3, w - 6, h - 6);

    item.texture.needsUpdate = true;
  }

  private createFloatingCubes(isMobile: boolean): void {
    const count = isMobile ? 18 : 36;
    const colors = [0x00f0ff, 0xff007f, 0xa855f7, 0x00ff66, 0xff7700];

    for (let i = 0; i < count; i++) {
      const size = 1.0 + Math.random() * 2.2;
      const geo = new THREE.BoxGeometry(size, size, size);
      const col = colors[i % colors.length];
      const mat = new THREE.MeshBasicMaterial({
        color: col,
        wireframe: true,
        transparent: true,
        opacity: 0.65
      });
      const cube = new THREE.Mesh(geo, mat);

      cube.position.set(
        (Math.random() - 0.5) * 70,
        3 + Math.random() * 25,
        10 - Math.random() * 320
      );

      cube.userData = {
        rotX: (Math.random() - 0.5) * 0.02,
        rotY: (Math.random() - 0.5) * 0.02,
        floatSpeed: 0.5 + Math.random() * 1.5,
        baseY: cube.position.y
      };

      this.scene.add(cube);
      this.floatingCubes.push(cube);
    }
  }

  private createStarfield(isMobile: boolean): void {
    const starCount = isMobile ? 500 : 1500;
    const geo = new THREE.BufferGeometry();
    const positions = new Float32Array(starCount * 3);

    for (let i = 0; i < starCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 350;
      positions[i + 1] = 12 + Math.random() * 150;
      positions[i + 2] = 20 - Math.random() * 450;
    }

    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const mat = new THREE.PointsMaterial({
      color: 0xddeeff,
      size: 1.0,
      transparent: true,
      opacity: 0.8
    });

    this.starSystem = new THREE.Points(geo, mat);
    this.scene.add(this.starSystem);
  }

  private animate = (): void => {
    if (!this.is3dEnabled) return;
    this.animId = requestAnimationFrame(this.animate);

    const elapsedTime = this.clock.getElapsedTime();

    // 1. Smooth Scroll Lerp for Camera Flight through Highway
    this.currentProgress += (this.targetProgress - this.currentProgress) * 0.12;

    // Camera travels from Z = 23.0 down to Z = -252.0 (spanning all 6 cabinets from 0 to -275)
    const targetCamZ = 23.0 - (this.currentProgress * 275);
    this.camera.position.z = targetCamZ;

    // Harmonic lateral sway: smoothly alternates framing based on active module
    const modFloat = this.currentProgress * 5;
    const sideFactor = Math.cos(modFloat * Math.PI); // +1.0 on even modules (Right machine), -1.0 on odd modules (Left machine)

    const targetCamX = -sideFactor * 1.2 + Math.sin(elapsedTime * 0.25) * 0.15;
    this.camera.position.x = targetCamX;
    this.camera.position.y = 4.6 + Math.sin(elapsedTime * 0.5) * 0.08;

    // Look at the active machine ahead (aimed right at CRT screen y = 4.4 for perfect vertical balance)
    const targetLookX = sideFactor * 2.5;
    this.camera.lookAt(targetLookX, 4.4, targetCamZ - 22.5);

    // Keep camera headlights locked right in front of the camera
    this.cameraLight.position.set(this.camera.position.x, this.camera.position.y, this.camera.position.z - 4);
    this.cameraDirLight.position.set(this.camera.position.x, this.camera.position.y + 4, this.camera.position.z - 2);

    // Continuous Tron floor glide
    if (this.gridHelper) {
      this.gridHelper.position.z = -180 + ((elapsedTime * 3) % 4);
    }

    // 2. Animate CRT Screens (vibrant radar sweep & scanlines)
    this.screenCanvases.forEach(item => {
      this.updateScreenTexture(item, elapsedTime);
    });

    // 3. Floating cubes rotation
    this.floatingCubes.forEach((cube, i) => {
      cube.rotation.x += cube.userData['rotX'];
      cube.rotation.y += cube.userData['rotY'];
      cube.position.y = cube.userData['baseY'] + Math.sin(elapsedTime * cube.userData['floatSpeed'] + i) * 1.2;
    });

    // 4. Subtle pulsing of light pillars
    this.pillars.forEach((p, idx) => {
      const pulse = 0.8 + Math.sin(elapsedTime * 2.5 + idx * 0.8) * 0.2;
      (p.material as THREE.MeshBasicMaterial).opacity = pulse;
    });

    // 5. Starfield drift
    if (this.starSystem) {
      this.starSystem.rotation.y = elapsedTime * 0.012;
    }

    this.renderer.render(this.scene, this.camera);
  };

  private pauseRenderLoop(): void {
    if (this.animId) {
      cancelAnimationFrame(this.animId);
      this.animId = undefined;
    }
  }

  private resumeRenderLoop(): void {
    if (!this.animId) {
      this.ngZone.runOutsideAngular(() => {
        this.animate();
      });
    }
  }

  private disposeThree(): void {
    this.pauseRenderLoop();

    if (this.scene) {
      this.scene.traverse((obj) => {
        if (obj instanceof THREE.Mesh || obj instanceof THREE.Points) {
          if (obj.geometry) obj.geometry.dispose();
          if (obj.material) {
            if (Array.isArray(obj.material)) {
              obj.material.forEach((m) => m.dispose());
            } else {
              obj.material.dispose();
            }
          }
        }
      });
    }

    if (this.renderer) {
      this.renderer.dispose();
    }
  }
}
