import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', loadComponent: () => import('./components/siem/dashboard/siem-dashboard.component').then(m => m.SiemDashboardComponent) },
  { path: 'agents',    loadComponent: () => import('./pages/siem/agents/siem-agents').then(m => m.SiemAgentsPage) },
  { path: 'rules',     loadComponent: () => import('./pages/siem/rules/siem-rules').then(m => m.SiemRulesPage) },
  { path: 'logs',      loadComponent: () => import('./pages/siem/logs/siem-logs').then(m => m.SiemLogsPage) },
  { path: 'alerts',    loadComponent: () => import('./pages/siem/alerts/siem-alerts').then(m => m.SiemAlertsPage) },
];
