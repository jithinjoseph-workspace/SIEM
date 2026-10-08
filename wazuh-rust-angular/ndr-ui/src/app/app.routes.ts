import { Routes } from '@angular/router';
import { provideCharts, withDefaultRegisterables } from 'ng2-charts';
import { authGuard } from '../services/auth/auth-guard';
import { homeGuard } from './home.guard';

export const routes: Routes = [
  // Smart home redirect — sends user to the right dashboard based on installed product
  { path: '', pathMatch: 'full', canActivate: [homeGuard], loadComponent: () => import('../pages/login/login').then(m => m.Login) },
  {
    path: 'login',
    loadComponent: () => import('../pages/login/login')
      .then(m => m.Login)
  },

  /* ── ANALYST pages (wrapped by AnalystLayout → .analyst-shell) ─── */
  {
    path: 'analyst',
    canActivate: [authGuard],
    loadComponent: () => import('../layout/analyst-layout/analyst-layout')
      .then(m => m.AnalystLayout),
    children: [
      { path: 'dashboard',   canActivate: [authGuard], data: { role: 'analyst' }, loadComponent: () => import('../pages/analyst/dashboard/dashboard').then(m => m.Dashboard) },
      { path: 'alerts',      canActivate: [authGuard], data: { role: 'analyst', permission: 'alerts'      }, loadComponent: () => import('../pages/analyst/alerts/alerts').then(m => m.Alerts) },
      { path: 'triage',      canActivate: [authGuard], data: { role: 'analyst', permission: 'alerts'      }, loadComponent: () => import('../pages/analyst/triage/triage').then(m => m.Triage) },
      { path: 'logs',        canActivate: [authGuard], data: { role: 'analyst', permission: 'logs'        }, loadComponent: () => import('../pages/analyst/logs/logs').then(m => m.Logs) },
      { path: 'live',        canActivate: [authGuard], data: { role: 'analyst', permission: 'live'        }, loadComponent: () => import('../pages/analyst/live/live').then(m => m.Live) },
      { path: 'intel',       canActivate: [authGuard], data: { role: 'analyst', permission: 'intel'       }, loadComponent: () => import('../pages/analyst/intel/intel').then(m => m.Intel) },
      { path: 'health',      canActivate: [authGuard], data: { role: 'analyst', permission: 'health'      }, loadComponent: () => import('../pages/analyst/health/health').then(m => m.Health) },
      { path: 'network-map', canActivate: [authGuard], data: { role: 'analyst', permission: 'network-map' }, loadComponent: () => import('../pages/analyst/network-map/network-map').then(m => m.NetworkMap) },
      { path: 'soar',        canActivate: [authGuard], data: { role: 'analyst', permission: 'soar'        }, loadComponent: () => import('../pages/analyst/soar/soar').then(m => m.Soar) },
      { path: 'evidence',    canActivate: [authGuard], data: { role: 'analyst', permission: 'evidence'    }, loadComponent: () => import('../pages/analyst/evidence/evidence').then(m => m.EvidenceComponent) },
      { path: 'ai-activity', canActivate: [authGuard], data: { role: 'analyst', permission: 'ai-activity' }, loadComponent: () => import('../pages/analyst/ai-activity/ai-activity').then(m => m.AiActivity) },
      { path: 'threat-map',  canActivate: [authGuard], data: { role: 'analyst' }, loadComponent: () => import('../pages/analyst/threat-map/threat-map').then(m => m.ThreatMap) },
      { path: 'ai-report',   canActivate: [authGuard], data: { role: 'analyst', permission: 'ai-report'   }, loadComponent: () => import('../pages/analyst/ai-report/ai-report').then(m => m.AiReport) },
      { path: 'assets',      canActivate: [authGuard], data: { role: 'analyst', permission: 'assets'      }, loadComponent: () => import('../pages/analyst/assets/assets').then(m => m.Assets) },
      { path: 'rules',       canActivate: [authGuard], data: { permission: 'rules'                        }, loadComponent: () => import('../pages/analyst/rules/rules').then(m => m.Rules) },
      { path: 'setup',       canActivate: [authGuard], data: { permission: 'setup'                        }, loadComponent: () => import('../pages/analyst/setup/setup').then(m => m.Setup) },
      { path: 'settings',    canActivate: [authGuard], loadComponent: () => import('../pages/analyst/settings/settings').then(m => m.Settings) },
      { path: 'support',        canActivate: [authGuard], loadComponent: () => import('../pages/analyst/support/support').then(m => m.Support) },
      { path: 'honeypots',      canActivate: [authGuard], data: { permission: 'honeypots'     }, loadComponent: () => import('../pages/analyst/honeypots/honeypots').then(m => m.Honeypots) },
      { path: 'retrospective',  canActivate: [authGuard], data: { permission: 'retrospective' }, loadComponent: () => import('../pages/analyst/retrospective/retrospective').then(m => m.Retrospective) },
    ]
  },

  /* ── XDR unified pages — all authenticated users ──────────────────── */
  {
    path: 'xdr',
    canActivate: [authGuard],
    loadComponent: () => import('../layout/analyst-layout/analyst-layout').then(m => m.AnalystLayout),
    children: [
      {
        path: 'alerts',
        canActivate: [authGuard],
        data: { permission: 'alerts' },
        loadComponent: () => import('../pages/xdr/alerts/xdr-alerts').then(m => m.XdrAlerts),
      },
    ],
  },

  /* ── SIEM pages — all embedded in analyst dashboard or moved to admin/tenant-admin ── */
  { path: 'siem/dashboard', redirectTo: '/analyst/dashboard',        pathMatch: 'full' },
  { path: 'siem/logs',      redirectTo: '/analyst/dashboard',        pathMatch: 'full' },
  { path: 'siem/sources',   redirectTo: '/tenant-admin/siem-sources', pathMatch: 'full' },

  /* ── ADMIN pages ──────────────────────────────────────────────────── */
  {
    path: 'admin',
    canActivate: [authGuard],
    data: { role: 'admin' },
    loadComponent: () => import('../layout/admin-layout/admin-layout').then(m => m.AdminLayout),
    children: [
      { path: '', redirectTo: 'overview', pathMatch: 'full' },
      { path: 'overview',        loadComponent: () => import('../pages/admin/overview/overview').then(m => m.Overview) },
      { path: 'tenants',         loadComponent: () => import('../pages/admin/tenants/tenants').then(m => m.Tenants) },
      { path: 'users',           loadComponent: () => import('../pages/admin/users/users').then(m => m.Users) },
      { path: 'engines',         loadComponent: () => import('../pages/admin/engines/engines').then(m => m.Engines) },
      { path: 'sensors',         loadComponent: () => import('../pages/admin/sensors/sensors').then(m => m.Sensors) },
      { path: 'announcements',   loadComponent: () => import('../pages/admin/announcements/announcements').then(m => m.Announcements) },
      { path: 'rules',           loadComponent: () => import('../pages/admin/rules/rules').then(m => m.AdminRules) },
      { path: 'telemetry',       loadComponent: () => import('../pages/admin/telemetry/telemetry').then(m => m.Telemetry) },
      { path: 'ai-providers',    loadComponent: () => import('../pages/admin/ai-providers/ai-providers').then(m => m.AiProviders) },
      { path: 'trusted-cloud',   loadComponent: () => import('../pages/admin/trusted-cloud/trusted-cloud').then(m => m.TrustedCloud) },
      { path: 'trusted-domains', loadComponent: () => import('../pages/admin/trusted-domains/trusted-domains').then(m => m.TrustedDomains) },
      { path: 'smtp-config',     loadComponent: () => import('../pages/admin/smtp-config/smtp-config').then(m => m.SmtpConfig) },
      { path: 'support',         loadComponent: () => import('../pages/admin/support/support').then(m => m.Support) },
      { path: 'siem-sources',    loadComponent: () => import('../pages/siem/sources/siem-sources').then(m => m.SiemSources) },
    ]
  },

  /* ── TENANT ADMIN pages ───────────────────────────────────────────── */
  {
    path: 'tenant-admin',
    canActivate: [authGuard],
    loadComponent: () => import('../layout/tenant-admin-layout/tenant-admin-layout')
      .then(m => m.TenantAdminLayout),
    children: [
      { path: '',               redirectTo: 'users', pathMatch: 'full' },
      { path: 'users',          loadComponent: () => import('../pages/tenant-admin/users/users').then(m => m.UsersSection),
                                 providers: [provideCharts(withDefaultRegisterables())] },
      { path: 'trusted-domains',loadComponent: () => import('../pages/tenant-admin/trusted-domains/trusted-domains').then(m => m.TrustedDomains) },
      { path: 'sessions',       loadComponent: () => import('../pages/tenant-admin/sessions/sessions').then(m => m.Sessions) },
      { path: 'profile',        loadComponent: () => import('../pages/tenant-admin/profile/profile').then(m => m.Profile) },
      { path: 'setup',          loadComponent: () => import('../pages/tenant-admin/setup/setup').then(m => m.Setup) },
      { path: 'siem-sources',   loadComponent: () => import('../pages/siem/sources/siem-sources').then(m => m.SiemSources) },
      { path: 'settings',       loadComponent: () => import('../pages/tenant-admin/settings/settings').then(m => m.TenantSettings) },
      { path: 'support',        loadComponent: () => import('../pages/tenant-admin/support/support').then(m => m.TenantSupport) },
    ]
  },

  { path: '**', redirectTo: 'login' }
];
