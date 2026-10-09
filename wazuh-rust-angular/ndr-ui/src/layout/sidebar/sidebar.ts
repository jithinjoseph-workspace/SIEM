import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Subscription } from 'rxjs';
import {
  LayoutDashboard, Bell, FileText, ShieldAlert, Search,
  Database, Settings, Network, Zap, FolderSearch, Bot, Server,
  ChevronDown, Map as MapIcon, Shield, RotateCcw,
  Radio, BarChart2, ScrollText, ListChecks,
  Cpu, Bug, ShieldCheck, FileCheck, Terminal, Monitor, Globe,
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
}

/**
 * Analysts see the SIEM pages only while the product is developed as a SIEM.
 * Set to true to bring back the NDR pages (dashboard, alerts, triage, attack
 * map, network, NDR rules, SOAR, evidence, AI activity, ...).
 */
const SHOW_NDR_PAGES = false;

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

    const hasNdr = SHOW_NDR_PAGES && this.auth.hasFeature('ndr');

    const overviewItems: NavItem[] = [];
    // Dashboard is universal — shows NDR section, SIEM section, or both depending on product mode
    if (SHOW_NDR_PAGES && (has('dashboard') || (this.auth.hasFeature('siem') && has('siem-dashboard')))) overviewItems.push({ label: 'Dashboard', route: '/analyst/dashboard', icon: LayoutDashboard, permission: 'dashboard' });

    const threatItems: NavItem[] = [];
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Alerts',       route: '/analyst/alerts',     icon: Bell,    permission: 'alerts' });
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Alert Triage', route: '/analyst/triage',     icon: ListChecks, permission: 'alerts' });
    if (hasNdr && has('intel'))  threatItems.push({ label: 'Threat Intel', route: '/analyst/intel',       icon: Search,  permission: 'intel'  });
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

    // SIEM section — unified host, fleet & security detection suite
    const hasSiem = this.auth.hasFeature('siem');
    // Each SIEM page needs the tenant's 'siem' feature and its own page permission.
    const siemCandidates: NavItem[] = [
      { label: 'Agent Fleet',         route: '/analyst/agents',          icon: Server,      permission: 'siem-agents' },
      { label: 'Dynamic Parsers',     route: '/analyst/siem-classic/console/parsers',             icon: Cpu,         permission: 'siem-parsers' },
      { label: 'MITRE ATT&CK',        route: '/analyst/mitre',           icon: Shield,      permission: 'siem-mitre' },
      { label: 'Vulnerabilities',     route: '/analyst/vulnerabilities', icon: Bug,         permission: 'siem-vulnerabilities' },
      { label: 'Compliance Audit',    route: '/analyst/siem-classic/console/compliance',          icon: ShieldCheck, permission: 'siem-compliance' },
      { label: 'FIM Syscheck',        route: '/analyst/siem-classic/console/fim',                 icon: FileCheck,   permission: 'siem-fim' },
      { label: 'Active Response',     route: '/analyst/active-response', icon: Zap,         permission: 'siem-active-response' },
      { label: 'Logtest Console',     route: '/analyst/logtest',         icon: Terminal,    permission: 'siem-logtest' },
    ];
    const siemItems: NavItem[] = hasSiem ? siemCandidates.filter(i => has(i.permission!)) : [];
    // Data source management is a tenant-admin page; analysts never get it in their sidebar.

    // Pages copied from frontend-angular (/analyst/siem-classic/*), same permission model.
    // SIEM console tabs (copied from frontend-angular), each its own page.
    const consoleCandidates: NavItem[] = [
      { label: 'Threat Overview',     route: '/analyst/siem-classic/console/overview',   icon: Globe,       permission: 'siem-dashboard' },
      { label: 'SIEM Alerts',         route: '/analyst/siem-classic/console/alerts',     icon: Bell,        permission: 'siem-alerts' },
      { label: 'Telemetry Stream',    route: '/analyst/siem-classic/console/telemetry',  icon: ScrollText,  permission: 'siem-logs' },
      { label: 'Wazuh Rules',         route: '/analyst/siem-classic/console/rules',      icon: ShieldAlert, permission: 'siem-rules' },
      { label: 'Attack Simulator',    route: '/analyst/siem-classic/console/simulator',  icon: Zap,         permission: 'siem-console' },
      { label: 'AI Copilot',          route: '/analyst/siem-classic/console/copilot',    icon: Bot,         permission: 'siem-console' },
      { label: '3D XDR Matrix',       route: '/analyst/siem-classic/console/xdr-3d',     icon: Shield,      permission: 'siem-console' },
      { label: 'Full SIEM Console',   route: '/analyst/siem-classic/console',            icon: Monitor,     permission: 'siem-console' },
    ];
    const consoleItems: NavItem[] = hasSiem ? consoleCandidates.filter(i => has(i.permission!)) : [];

    // The standalone frontend-angular pages, kept as they were.
    const classicCandidates: NavItem[] = [
      { label: 'Classic Overview',    route: '/analyst/siem-classic/overview',  icon: LayoutDashboard, permission: 'siem-dashboard' },
      { label: 'Classic Dashboard',   route: '/analyst/siem-classic/dashboard', icon: BarChart2,   permission: 'siem-dashboard' },
      { label: 'Classic Agents',      route: '/analyst/siem-classic/agents',    icon: Server,      permission: 'siem-agents' },
      { label: 'Classic Alerts',      route: '/analyst/siem-classic/alerts',    icon: Bell,        permission: 'siem-alerts' },
      { label: 'Classic Logs',        route: '/analyst/siem-classic/logs',      icon: ScrollText,  permission: 'siem-logs' },
      { label: 'Classic Rules',       route: '/analyst/siem-classic/rules',     icon: ShieldAlert, permission: 'siem-rules' },
      { label: 'Classic Sources',     route: '/analyst/siem-classic/sources',   icon: Radio,       permission: 'siem-sources' },
    ];
    const classicItems: NavItem[] = hasSiem ? classicCandidates.filter(i => has(i.permission!)) : [];

    // XDR Correlated Incidents — available when both NDR & SIEM are enabled
    if (hasNdr && hasSiem && has('alerts')) {
      threatItems.unshift({ label: 'XDR Incidents', route: '/xdr/alerts', icon: Shield });
    }

    this.navGroups = [
      ...(overviewItems.length  ? [{ section: 'OVERVIEW',  collapsed: false, items: overviewItems  }] : []),
      ...(threatItems.length    ? [{ section: 'THREATS',   collapsed: false, items: threatItems    }] : []),
      ...(siemItems.length      ? [{ section: 'SIEM & HOSTS', collapsed: false, items: siemItems   }] : []),
      ...(consoleItems.length   ? [{ section: 'SIEM CONSOLE', collapsed: false, items: consoleItems }] : []),
      ...(classicItems.length   ? [{ section: 'SIEM CLASSIC PAGES', collapsed: true, items: classicItems }] : []),
      ...(networkItems.length   ? [{ section: 'NETWORK',   collapsed: false, items: networkItems   }] : []),
      ...(enforceItems.length   ? [{ section: 'ENFORCE',   collapsed: false, items: enforceItems   }] : []),
      ...(systemItems.length    ? [{ section: 'SYSTEM',    collapsed: false, items: systemItems    }] : []),
      ...(responseItems.length  ? [{ section: 'RESPONSE',  collapsed: false, items: responseItems  }] : []),
      ...(intelItems.length     ? [{ section: 'INTEL',     collapsed: false, items: intelItems     }] : []),
    ];

    // Restore any previously collapsed groups so navigation doesn't reset them
    this.navGroups.forEach(g => {
      if (collapsed.has(g.section)) g.collapsed = collapsed.get(g.section)!;
    });
  }
}
