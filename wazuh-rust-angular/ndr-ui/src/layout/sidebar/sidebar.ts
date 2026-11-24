import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Subscription } from 'rxjs';
import {
  LayoutDashboard, Bell, FileText, ShieldAlert, Search,
  Database, Settings, Network, Zap, FolderSearch, Bot, Server,
  ChevronDown, Map as MapIcon, Shield, RotateCcw,
  ScrollText, ListChecks,
  Cpu, Bug, ShieldCheck, FileCheck, Terminal, Monitor, Globe,
  ListFilter, EyeOff, Crosshair, Gauge, Brain, Share2, Target, Sparkles, Scale, ScanSearch, FileSearch,
  LucideAngularModule
} from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';

interface NavItem {
  label: string;
  route: string;
  icon: any;
  permission?: string;
  queryParams?: Record<string, string>;
}

interface NavGroup {
  section: string;
  collapsed: boolean;
  items: NavItem[];
  /** The module heading shown above the module's first group (NDR, SIEM) when both are licensed. */
  product?: string;
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.css',
})
export class Sidebar implements OnInit, OnDestroy {
  navGroups: NavGroup[] = [];
  ChevronDownIcon = ChevronDown;
  private navigationSub?: Subscription;

  constructor(private auth: AuthService, private router: Router) {}

  ngOnInit() {
    this.buildNavigation();
  }

  trackGroup(index: number, group: NavGroup) {
    return group.section;
  }

  trackItem(index: number, item: NavItem) {
    return item.route;
  }

  ngOnDestroy() { this.navigationSub?.unsubscribe(); }

  toggleGroup(group: NavGroup) { group.collapsed = !group.collapsed; }

  isActive(item: NavItem): boolean {
    if (item.queryParams) {
      const tree = this.router.createUrlTree([item.route], { queryParams: item.queryParams });
      return this.router.isActive(tree, { paths: 'exact', queryParams: 'exact', fragment: 'ignored', matrixParams: 'ignored' });
    }
    return this.router.isActive(item.route, { paths: 'exact', queryParams: 'ignored', fragment: 'ignored', matrixParams: 'ignored' });
  }

  private buildNavigation() {
    // Preserve collapsed state across navigation rebuilds
    const collapsed = new Map<string, boolean>();
    this.navGroups.forEach(g => collapsed.set(g.section, g.collapsed));
 
    const user = this.auth.getUser();
    const isDefaultTenant = user?.tenant_id === 'default';
 
    const has = (p: string) => this.auth.hasPermission(p);

    // NDR pages follow the client's licence (the `ndr` feature), like the SIEM ones follow `siem`
    const hasNdr = this.auth.hasFeature('ndr');

    const overviewItems: NavItem[] = [];
    // Overview: one page, NDR's overview then the SIEM overview (each when licensed); a SIEM-only
    // client's Overview is the SIEM overview page
    const overviewHasSiem = this.auth.hasFeature('siem') && has('siem-dashboard');
    if (hasNdr && (has('dashboard') || overviewHasSiem)) overviewItems.push({ label: 'Overview', route: '/analyst/dashboard', icon: LayoutDashboard, permission: 'dashboard' });
    else if (overviewHasSiem) overviewItems.push({ label: 'Overview', route: '/analyst/siem-classic/console/overview', icon: LayoutDashboard, permission: 'siem-dashboard' });

    const threatItems: NavItem[] = [];
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Alerts',       route: '/analyst/alerts',     icon: Bell,    permission: 'alerts' });
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Alert Triage', route: '/analyst/triage',     icon: ListChecks, permission: 'alerts' });
    if (hasNdr && has('intel') && this.auth.hasFeature('threat_intel'))  threatItems.push({ label: 'Threat Intel', route: '/analyst/intel',       icon: Search,  permission: 'intel'  });
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Attack Map',   route: '/analyst/threat-map',  icon: MapIcon, permission: 'alerts' });

    const networkItems: NavItem[] = [];
    if (hasNdr && has('logs'))        networkItems.push({ label: 'Network',     route: '/analyst/logs',        icon: FileText, permission: 'logs'        });
    if (hasNdr && has('network-map')) networkItems.push({ label: 'Network Map', route: '/analyst/network-map', icon: Network,  permission: 'network-map' });
    if (hasNdr && has('assets'))      networkItems.push({ label: 'Assets',      route: '/analyst/assets',      icon: Server,   permission: 'assets'      });

    const enforceItems: NavItem[] = [];
    if (hasNdr && has('rules'))       enforceItems.push({ label: 'Rules',         route: '/analyst/rules',         icon: ShieldAlert, permission: 'rules'  });
    if (hasNdr && has('retrospective')) enforceItems.push({ label: 'Retrospective', route: '/analyst/retrospective', icon: RotateCcw,   permission: 'retrospective' });
    if (hasNdr && has('honeypots'))   enforceItems.push({ label: 'Honeypots',     route: '/analyst/honeypots',     icon: Shield,      permission: 'honeypots' });

    const systemItems: NavItem[] = [];
    if (hasNdr && has('health')) systemItems.push({ label: 'System Health', route: '/analyst/health', icon: Database, permission: 'health' });
    if (hasNdr && isDefaultTenant && has('setup')) systemItems.push({ label: 'Sensor Setup', route: '/analyst/setup', icon: Settings, permission: 'setup' });

    const responseItems: NavItem[] = [];
    if (hasNdr && has('soar') && this.auth.hasFeature('soar'))
      responseItems.push({ label: 'SOAR', route: '/analyst/soar', icon: Zap, permission: 'soar' });
    if (hasNdr && has('evidence')) responseItems.push({ label: 'Evidence', route: '/analyst/evidence', icon: FolderSearch, permission: 'evidence' });

    const intelItems: NavItem[] = [];
    if (hasNdr && has('ai-activity') && this.auth.isTenantAiEnabled())
      intelItems.push({ label: 'AI Activity', route: '/analyst/ai-activity', icon: Bot, permission: 'ai-activity' });

    // SIEM: the menu follows the SOC's work: watch, investigate and respond, the hosts'
    // posture, detection engineering, threat intel, and oversight of the AI.
    const hasSiem = this.auth.hasFeature('siem');
    // licence modules beyond SIEM/NDR: AI pages and threat-intel pages
    const aiOn = this.auth.isTenantAiEnabled();
    const intelOn = this.auth.hasFeature('threat_intel');
    const AI_PAGES = ['/analyst/siem-copilot'];
    const INTEL_PAGES = ['/analyst/siem-threat-intel', '/analyst/siem-swarm'];
    const byModule = (i: NavItem) => (aiOn || !AI_PAGES.includes(i.route)) && (intelOn || !INTEL_PAGES.includes(i.route));
    const siemGroup = (items: NavItem[]) => hasSiem ? items.filter(i => has(i.permission!) && byModule(i)) : [];
    const monitorItems = siemGroup([
      { label: 'Alerts',              route: '/analyst/siem-classic/console/alerts',    icon: Bell,        permission: 'siem-alerts' },
      { label: 'Alert Triage',        route: '/analyst/siem-triage',                    icon: ListFilter,  permission: 'siem-alerts' },
      { label: 'Telemetry',           route: '/analyst/siem-classic/console/telemetry', icon: ScrollText,  permission: 'siem-logs' },
    ]);
    const respondItems = siemGroup([
      { label: 'AI Copilot',          route: '/analyst/siem-copilot',     icon: Bot,         permission: 'siem-alerts' },
      { label: 'Investigation',       route: '/analyst/siem-investigate', icon: ScanSearch,  permission: 'siem-alerts' },
      { label: 'Active Response',     route: '/analyst/active-response',  icon: Zap,         permission: 'siem-active-response' },
    ]);
    // the per-tenant SOAR (cases and playbooks; one page for NDR and SIEM)
    if (hasSiem && !hasNdr && has('soar') && this.auth.hasFeature('soar'))
      respondItems.splice(2, 0, { label: 'Cases & Playbooks', route: '/analyst/soar', icon: FolderSearch, permission: 'soar' });
    const postureItems = siemGroup([
      { label: 'Agent Fleet',         route: '/analyst/agents',          icon: Server,      permission: 'siem-agents' },
      { label: 'Vulnerabilities',     route: '/analyst/vulnerabilities', icon: Bug,         permission: 'siem-vulnerabilities' },
      { label: 'Compliance',          route: '/analyst/compliance',      icon: ShieldCheck, permission: 'siem-compliance' },
      { label: 'File Integrity (FIM)', route: '/analyst/fim',            icon: FileCheck,   permission: 'siem-fim' },
      { label: 'MITRE ATT&CK',        route: '/analyst/mitre',           icon: Shield,      permission: 'siem-mitre' },
    ]);
    const detectionItems = siemGroup([
      { label: 'Rules',               route: '/analyst/siem-rules',          icon: ShieldAlert, permission: 'siem-rules' },
      { label: 'Sigma Detection',     route: '/analyst/siem-sigma',          icon: FileSearch,  permission: 'siem-rules' },
      { label: 'Dynamic Parsers',     route: '/analyst/parsers',             icon: Cpu,         permission: 'siem-parsers' },
      { label: 'Logtest',             route: '/analyst/logtest',             icon: Terminal,    permission: 'siem-logtest' },
      { label: 'Retrospective',       route: '/analyst/siem-retrospective',  icon: RotateCcw,   permission: 'siem-rules' },
      { label: 'Suppressions',        route: '/analyst/siem-suppressions',   icon: EyeOff,      permission: 'siem-alerts' },
    ]);
    const intelSiemItems = siemGroup([
      { label: 'Threat Intel',        route: '/analyst/siem-threat-intel',  icon: Globe,     permission: 'siem-alerts' },
      { label: 'Security Posture',    route: '/analyst/siem-posture',       icon: ShieldCheck, permission: 'siem-alerts' },
      { label: 'Threat Predictions',  route: '/analyst/siem-predictions',   icon: Crosshair, permission: 'siem-mitre' },
      { label: 'Threat Swarm',        route: '/analyst/siem-swarm',         icon: Share2,    permission: 'siem-alerts' },
      { label: 'Intent Radar', route: '/analyst/intent-prediction', icon: Target,   permission: 'siem-agents' },
      { label: 'Risk Fabric',         route: '/analyst/risk-fabric',        icon: Network,   permission: 'siem-agents' },
      { label: 'Red Swarm', route: '/analyst/redswarm',       icon: Zap,       permission: 'siem-mitre' },
      { label: 'Deception', route: '/analyst/deception',         icon: Sparkles,  permission: 'siem-agents' },
    ]);
    const oversightItems = siemGroup([
      { label: 'AI Oversight',        route: '/analyst/siem-ai-oversight',  icon: Scale,     permission: 'siem-alerts' },
    ]).filter(() => aiOn);

    // XDR incidents (a host alert and an NDR detection on the same host): with both modules only
    if (hasNdr && hasSiem && has('alerts')) {
      overviewItems.push({ label: 'XDR Incidents', route: '/xdr/alerts', icon: Shield });
    }

    // Overview first, then every NDR page, then every SIEM page; a module heading above each
    // module's groups when the client has both
    const group = (section: string, items: NavItem[]): NavGroup[] => items.length ? [{ section, collapsed: false, items }] : [];
    const product = (name: string, groups: NavGroup[]): NavGroup[] => {
      if (hasNdr && hasSiem && groups.length) groups[0].product = name;
      return groups;
    };
    this.navGroups = [
      ...group('OVERVIEW', overviewItems),
      ...product('NDR', [
        ...group('THREATS', threatItems),
        ...group('NETWORK', networkItems),
        ...group('ENFORCE', enforceItems),
        ...group('RESPONSE', responseItems),
        ...group('INTEL', intelItems),
        ...group('SYSTEM', systemItems),
      ]),
      ...product('SIEM', [
        ...group('MONITOR', monitorItems),
        ...group('INVESTIGATE & RESPOND', respondItems),
        ...group('HOSTS & POSTURE', postureItems),
        ...group('DETECTION', detectionItems),
        ...group('THREAT INTEL', intelSiemItems),
        ...group('AI OVERSIGHT', oversightItems),
      ]),
    ];

    // Restore any previously collapsed groups so navigation doesn't reset them
    this.navGroups.forEach(g => {
      if (collapsed.has(g.section)) g.collapsed = collapsed.get(g.section)!;
    });
  }
}
