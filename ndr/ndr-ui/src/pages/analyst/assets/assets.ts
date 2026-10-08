import { Component, OnInit, AfterViewInit, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import {
  LucideAngularModule,
  Server,
  Monitor,
  Smartphone,
  Printer,
  Router,
  Lightbulb,
  Search,
  Filter,
  Check,
  X,
  Edit,
  ChevronDown,
  ShieldCheck,
  ShieldOff,
  AlertTriangle,
  ArrowRight,
  Network
} from 'lucide-angular';

import { DeviceDrawer } from '../../../components/device-drawer/device-drawer';
import { AuthService } from '../../../services/auth/auth';

declare var echarts: any;
@Component({
  selector: 'app-assets',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule, DeviceDrawer],
  templateUrl: './assets.html',
  styleUrl: './assets.css',
})
export class Assets implements OnInit, AfterViewInit {
  ServerIcon = Server;
  MonitorIcon = Monitor;
  SmartphoneIcon = Smartphone;
  PrinterIcon = Printer;
  RouterIcon = Router;
  LightbulbIcon = Lightbulb;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = Check;
  XIcon = X;
  ShieldCheckIcon = ShieldCheck;
  ShieldOffIcon = ShieldOff;
  AlertTriangleIcon = AlertTriangle;
  EditIcon = Edit;
  ChevronDownIcon = ChevronDown;
  ArrowRightIcon = ArrowRight;
  NetworkIcon = Network;

  assets: any[] = [];
  filteredAssets: any[] = [];
  loading = true;
  searchTerm = '';
  filterDeviceType = 'all';
  filterSubnet = 'all';
  filterLast24h = false;
  editingIp: string | null = null;
  editNameValue = '';

  timeFilter = '24h';
  isTimeDropdownOpen = false;
  subnetSort = 'top';
  isSubnetSortDropdownOpen = false;

  setTimeFilter(val: string) {
    this.timeFilter = val;
    this.isTimeDropdownOpen = false;
    this.fetchAndRenderThreatLandscape();
  }

  setSubnetSort(val: string) {
    this.subnetSort = val;
    this.isSubnetSortDropdownOpen = false;
    if (val === 'top') {
      this.enrichedSubnets.sort((a, b) => b.assetCount - a.assetCount);
    } else {
      this.enrichedSubnets.sort((a, b) => a.assetCount - b.assetCount);
    }
  }

  subnets: any[] = [];
  isSubnetDropdownOpen = false;

  @ViewChild('sunburstContainer') sunburstContainer?: ElementRef;
  @ViewChild('threatLandscapeContainer') threatLandscapeContainer?: ElementRef;

  sunburstChart: any;
  threatLandscapeChart: any;
  enrichedSubnets: any[] = [];

  selectedAsset: any = null;

  isDropdownOpen = false;
  
  deviceTypeOptions = [
    { value: 'all', label: 'All Devices' },
    { value: 'laptop', label: 'Laptop' },
    { value: 'desktop', label: 'Desktop' },
    { value: 'phone', label: 'Phone / Mobile' },
    { value: 'tablet', label: 'Tablet' },
    { value: 'iot', label: 'IoT' },
    { value: 'printer', label: 'Printer' },
    { value: 'tv', label: 'TV / Media' },
    { value: 'server', label: 'Server' },
    { value: 'router', label: 'Router / Gateway' },
    { value: 'unknown', label: 'Unknown' }
  ];

  getFilterLabel(): string {
    const option = this.deviceTypeOptions.find(o => o.value === this.filterDeviceType);
    return option ? option.label : 'All Devices';
  }

  setFilter(value: string) {
    this.filterDeviceType = value;
    this.isDropdownOpen = false;
    this.filterAssets();
  }

  // Dashboard Stats
  totalAssets = 0;
  stats = {
    workstations: { count: 0, percent: 0 },
    servers: { count: 0, percent: 0 },
    iot: { count: 0, percent: 0 },
    networking: { count: 0, percent: 0 }
  };

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(private api: Api, private cdr: ChangeDetectorRef, private auth: AuthService) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.loadAssets();
    this.loadSubnets();
  }

  ngAfterViewInit() {
    // Small delay to ensure DOM is ready and visible
    setTimeout(() => {
      this.initCharts();
    }, 100);
  }

  initCharts() {
    if (typeof echarts === 'undefined') return;
    
    if (this.sunburstContainer && !this.sunburstChart) {
      this.sunburstChart = echarts.init(this.sunburstContainer.nativeElement, 'dark');
      this.updateSunburst();
    }
    
    if (this.threatLandscapeContainer && !this.threatLandscapeChart) {
      this.threatLandscapeChart = echarts.init(this.threatLandscapeContainer.nativeElement, 'dark');
      this.fetchAndRenderThreatLandscape();
    }
  }

  enrichSubnets() {
    if (!this.subnets || this.subnets.length === 0) return;
    if (!this.assets || this.assets.length === 0) {
       this.enrichedSubnets = [...this.subnets];
       return;
    }
    
    this.enrichedSubnets = this.subnets.map(s => {
      let count = 0;
      let roles: {[role: string]: number} = {};
      
      this.assets.forEach(a => {
        if (a.ip && this.isIpInCidr(a.ip, s.cidr)) {
          count++;
          const role = (a.role || a.device_type || 'UNKNOWN').toUpperCase();
          roles[role] = (roles[role] || 0) + 1;
        }
      });
      
      let dominant = 'UNKNOWN';
      let max = 0;
      for (const [r, c] of Object.entries(roles)) {
        if (c > max) { max = c; dominant = r; }
      }
      
      const pct = count ? Math.min(100, count * 5) : 0;
      
      return { ...s, assetCount: count, dominantRole: dominant, assetPercent: pct };
    });
    
    // Sort by assetCount desc
    this.enrichedSubnets.sort((a, b) => b.assetCount - a.assetCount);
  }

  updateSunburst() {
    if (!this.sunburstChart || this.assets.length === 0) return;
    
    const typeCount = {
      'Workstations': this.stats.workstations.count,
      'Servers': this.stats.servers.count,
      'IoT Devices': this.stats.iot.count,
      'Networking': this.stats.networking.count
    };
    const total = this.totalAssets;

    const pieData = [
      { name: 'Workstations', value: typeCount['Workstations'] },
      { name: 'Servers', value: typeCount['Servers'] },
      { name: 'IoT Devices', value: typeCount['IoT Devices'] },
      { name: 'Networking', value: typeCount['Networking'] }
    ];

    const colorPalette = [
      new echarts.graphic.LinearGradient(0, 0, 1, 1, [{offset: 0, color: '#5eb5ff'}, {offset: 1, color: '#005ee6'}]),
      new echarts.graphic.LinearGradient(0, 0, 1, 1, [{offset: 0, color: '#69f6b8'}, {offset: 1, color: '#008f52'}]),
      new echarts.graphic.LinearGradient(0, 0, 1, 1, [{offset: 0, color: '#ff8b84'}, {offset: 1, color: '#d60000'}]),
      new echarts.graphic.LinearGradient(0, 0, 1, 1, [{offset: 0, color: '#c084fc'}, {offset: 1, color: '#6a0dad'}])
    ];

    this.sunburstChart.setOption({
      backgroundColor: 'transparent',
      tooltip: { 
        trigger: 'item', 
        backgroundColor: 'rgba(10, 25, 47, 0.95)', 
        borderColor: '#00a2ff', 
        textStyle: { color: '#fff' } 
      },
      color: colorPalette,
      legend: {
        orient: 'vertical',
        left: '42%',
        top: 'center',
        itemGap: 18,
        icon: 'circle',
        itemWidth: 12,
        textStyle: {
          rich: {
            name: { color: '#cbd5e1', fontSize: 15, width: 110 },
            val: { color: '#ffffff', fontSize: 15, fontWeight: 'bold', width: 28, align: 'right' },
            pct: { color: '#64748b', fontSize: 15, width: 50, align: 'right' }
          }
        },
        formatter: (name: string) => {
          const data = pieData.find(d => d.name === name);
          const val = data ? data.value : 0;
          const pct = total ? Math.round((val / total) * 100) : 0;
          return `{name|${name}} {val|${val}} {pct|(${pct}%)}`;
        }
      },
      series: [
        {
          type: 'pie',
          radius: ['50%', '75%'],
          center: ['22%', '50%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#0a0f1a',
            borderWidth: 4,
            shadowBlur: 15,
            shadowColor: 'rgba(0, 0, 0, 0.4)'
          },
          label: {
            show: true,
            position: 'center',
            formatter: `{a|${total}}\n{b|Assets}`,
            rich: {
              a: {
                fontSize: 36,
                fontWeight: 900,
                color: '#ffffff',
                lineHeight: 40,
                textShadowColor: 'rgba(61, 158, 255, 0.5)',
                textShadowBlur: 15
              },
              b: {
                fontSize: 11,
                color: '#64748b',
                fontWeight: 600,
                letterSpacing: 2
              }
            }
          },
          labelLine: { show: false },
          data: pieData
        }
      ]
    }, true);
  }

  private parseAlertDate(value: any): number {
    if (value === null || value === undefined || value === '') return 0;
    if (typeof value === 'number') {
      return value > 9999999999 ? value : value * 1000;
    }
    const raw = String(value).trim();
    if (/^\d+$/.test(raw)) return this.parseAlertDate(Number(raw));
    const n = raw.includes('T') ? raw : raw.replace(' ', 'T');
    const z = /Z$|[+-]\d{2}:?\d{2}$/.test(n) ? n : `${n}Z`;
    const d = new Date(z);
    return isNaN(d.getTime()) ? 0 : d.getTime();
  }

  fetchAndRenderThreatLandscape() {
    if (!this.threatLandscapeChart) return;
    this.api.getAlerts().subscribe({
      next: (hits: any[]) => {
        const nowMs = Date.now();
        let bucketMs = 3600 * 1000; // 24h default
        let numBuckets = 24;
        let formatLabel = (d: Date) => `${d.getHours().toString().padStart(2, '0')}:00`;

        if (this.timeFilter === '7d') {
          bucketMs = 24 * 3600 * 1000;
          numBuckets = 7;
          formatLabel = (d: Date) => `${d.getMonth()+1}/${d.getDate()}`;
        } else if (this.timeFilter === '30d') {
          bucketMs = 24 * 3600 * 1000;
          numBuckets = 30;
          formatLabel = (d: Date) => `${d.getMonth()+1}/${d.getDate()}`;
        }
        
        const dataHigh = new Array(numBuckets).fill(0);
        const dataMedium = new Array(numBuckets).fill(0);
        const dataLow = new Array(numBuckets).fill(0);
        const dataInfo = new Array(numBuckets).fill(0);
        const labels: string[] = [];
        
        for (let i = numBuckets - 1; i >= 0; i--) {
          const d = new Date(nowMs - (i * bucketMs));
          labels.push(formatLabel(d));
        }

        hits.forEach(hit => {
          const ts = this.parseAlertDate(hit.timestamp || hit.ts);
          if (ts === 0) return;
          const diffMs = nowMs - ts;
          const index = (numBuckets - 1) - Math.floor(diffMs / bucketMs);
          
          if (index >= 0 && index < numBuckets) {
            const sev = (hit.severity || '').toUpperCase();
            if (sev === 'CRITICAL' || sev === 'HIGH') dataHigh[index]++;
            else if (sev === 'MEDIUM') dataMedium[index]++;
            else if (sev === 'LOW') dataLow[index]++;
            else dataInfo[index]++;
          }
        });

        this.threatLandscapeChart.setOption({
          backgroundColor: 'transparent',
          tooltip: {
            trigger: 'axis',
            backgroundColor: 'rgba(9, 18, 29, 0.9)',
            borderColor: 'rgba(255, 255, 255, 0.1)',
            textStyle: { color: '#ffffff' },
            axisPointer: { type: 'line', lineStyle: { color: 'rgba(255, 255, 255, 0.2)', type: 'dashed' } },
            formatter: (params: any[]) => {
              let res = `<div style="margin-bottom: 8px; font-size: 12px; color: #6b7a90">${params[0].axisValue}</div>`;
              params.forEach(p => {
                res += `<div style="display: flex; justify-content: space-between; gap: 20px; font-size: 13px;">
                          <div style="display: flex; align-items: center; gap: 6px;">
                            ${p.marker} <span>${p.seriesName}</span>
                          </div>
                          <strong>${p.value}</strong>
                        </div>`;
              });
              return res;
            }
          },
          grid: { top: 20, right: 20, bottom: 30, left: 40 },
          xAxis: {
            type: 'category',
            boundaryGap: false,
            data: labels,
            axisLine: { show: false },
            axisTick: { show: false },
            axisLabel: { color: '#6b7a90', fontSize: 11, margin: 12 }
          },
          yAxis: {
            type: 'value',
            splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)', type: 'dashed' } },
            axisLabel: { color: '#6b7a90', fontSize: 11 }
          },
          color: ['#005aff', '#009dff', '#ffa600', '#f43f5e'],
          series: [
            {
              name: 'Info', type: 'line', smooth: true, symbol: 'none',
              lineStyle: { width: 2 },
              areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: 'rgba(0, 90, 255, 0.3)' },
                  { offset: 1, color: 'rgba(0, 90, 255, 0.01)' }
                ])
              },
              data: dataInfo
            },
            {
              name: 'Low', type: 'line', smooth: true, symbol: 'none',
              lineStyle: { width: 2 },
              areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: 'rgba(0, 157, 255, 0.3)' },
                  { offset: 1, color: 'rgba(0, 157, 255, 0.01)' }
                ])
              },
              data: dataLow
            },
            {
              name: 'Medium', type: 'line', smooth: true, symbol: 'none',
              lineStyle: { width: 2 },
              areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: 'rgba(255, 166, 0, 0.3)' },
                  { offset: 1, color: 'rgba(255, 166, 0, 0.01)' }
                ])
              },
              data: dataMedium
            },
            {
              name: 'High', type: 'line', smooth: true, symbol: 'none',
              lineStyle: { width: 2 },
              areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: 'rgba(244, 63, 94, 0.3)' },
                  { offset: 1, color: 'rgba(244, 63, 94, 0.01)' }
                ])
              },
              data: dataHigh
            }
          ]
        });
      },
      error: () => {}
    });
  }

  loadSubnets() {
    this.api.getIpamSubnets().subscribe({
      next: (data: any[]) => { 
        this.subnets = Array.isArray(data) ? data : []; 
        this.enrichSubnets();
        setTimeout(() => {
          if (!this.threatLandscapeChart && this.threatLandscapeContainer && typeof echarts !== 'undefined') {
            this.threatLandscapeChart = echarts.init(this.threatLandscapeContainer.nativeElement, 'dark');
            this.fetchAndRenderThreatLandscape();
          }
        }, 100);
      },
      error: () => { this.subnets = []; }
    });
  }

  setSubnetFilter(cidr: string) {
    this.filterSubnet = cidr;
    this.isSubnetDropdownOpen = false;
    this.filterAssets();
  }

  getSubnetLabel(): string {
    if (this.filterSubnet === 'all') return 'All Subnets';
    return this.filterSubnet;
  }

  isIpInCidr(ip: string, cidr: string): boolean {
    const [net, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);
    const ipToNum = (s: string) => s.split('.').reduce((acc, o) => (acc << 8) | parseInt(o, 10), 0) >>> 0;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipToNum(ip) & mask) === (ipToNum(net) & mask);
  }

  loadAssets() {
    this.loading = true;
    this.api.getAssets().subscribe({
      next: (data: any) => {
        if (data && Array.isArray(data)) {
          this.assets = data;
        } else if (data && data.error) {
          console.error("Backend error:", data.error);
          this.assets = [];
        } else {
          console.warn("Unexpected data format:", data);
          this.assets = [];
        }
        this.calculateStats();
        this.filterAssets();
        this.enrichSubnets();
        this.loading = false;
        this.cdr.detectChanges();
        setTimeout(() => {
          this.initCharts();
          this.updateSunburst();
        }, 100);
      },
      error: (err) => {
        console.error("HTTP error:", err);
        this.assets = [];
        this.filterAssets();
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  calculateStats() {
    this.totalAssets = this.assets.length;
    
    let workstations = 0;
    let servers = 0;
    let iot = 0;
    let networking = 0;

    this.assets.forEach(a => {
      const type = (a.device_type || 'unknown').toLowerCase();
      if (type === 'server') {
        servers++;
      } else if (['iot', 'printer', 'tv'].includes(type)) {
        iot++;
      } else if (['router', 'network', 'gateway', 'switch', 'firewall'].includes(type)) {
        networking++;
      } else {
        workstations++;
      }
    });

    let pWorkstations = this.totalAssets ? Math.round((workstations / this.totalAssets) * 100) : 0;
    let pServers = this.totalAssets ? Math.round((servers / this.totalAssets) * 100) : 0;
    let pIot = this.totalAssets ? Math.round((iot / this.totalAssets) * 100) : 0;
    let pNetworking = this.totalAssets ? Math.round((networking / this.totalAssets) * 100) : 0;

    if (this.totalAssets > 0) {
      const diff = 100 - (pWorkstations + pServers + pIot + pNetworking);
      if (diff !== 0) {
        const max = Math.max(workstations, servers, iot, networking);
        if (max === workstations) pWorkstations += diff;
        else if (max === servers) pServers += diff;
        else if (max === iot) pIot += diff;
        else pNetworking += diff;
      }
    }

    this.stats = {
      workstations: { count: workstations, percent: pWorkstations },
      servers: { count: servers, percent: pServers },
      iot: { count: iot, percent: pIot },
      networking: { count: networking, percent: pNetworking }
    };
  }

  filterAssets() {
    const term = (this.searchTerm || '').toLowerCase();
    const now = Date.now() / 1000;
    
    this.filteredAssets = this.assets.filter(a => {
      // 0. Subnet Filter
      if (this.filterSubnet !== 'all') {
        if (!a.ip || !this.isIpInCidr(a.ip, this.filterSubnet)) return false;
      }

      // 1. Device Type Filter
      if (this.filterDeviceType !== 'all') {
        const type = (a.device_type || '').toLowerCase();
        let isMatch = type === this.filterDeviceType;
        
        // Handle synonyms for multi-term categories
        if (this.filterDeviceType === 'phone' && type === 'mobile') isMatch = true;
        if (this.filterDeviceType === 'tv' && type === 'media') isMatch = true;
        if (this.filterDeviceType === 'router' && (type === 'gateway' || type === 'firewall' || type === 'switch')) isMatch = true;
        
        if (!isMatch) return false;
      }
      
      // 2. 24h Filter
      if (this.filterLast24h) {
        // last_seen is a unix timestamp in seconds
        if (!a.last_seen || (now - a.last_seen) > 86400) {
          return false;
        }
      }
      
      // 3. Search Term Filter
      if (term) {
        const ip = (a.ip || '').toLowerCase();
        const mac = (a.mac || '').toLowerCase();
        const hostname = (a.hostname || '').toLowerCase();
        const custom_name = (a.custom_name || '').toLowerCase();
        const vendor = (a.vendor || '').toLowerCase();
        const device_type = (a.device_type || '').toLowerCase();
        
        // Hybrid Asset Model: also search inside ip_history JSON for historical IPs
        let historyMatch = false;
        if (a.ip_history && a.ip_history !== '[]') {
          try {
            const history: Array<{ip: string}> = JSON.parse(a.ip_history);
            historyMatch = history.some((entry: {ip: string}) =>
              entry.ip && entry.ip.toLowerCase().includes(term)
            );
          } catch { /* ignore malformed JSON */ }
        }
        
        return ip.includes(term) ||
               mac.includes(term) ||
               hostname.includes(term) ||
               custom_name.includes(term) ||
               vendor.includes(term) ||
               device_type.includes(term) ||
               historyMatch;
      }
      
      return true;
    });
  }

  getDeviceIcon(type: string) {
    switch(type?.toLowerCase()) {
      case 'laptop': return this.MonitorIcon;
      case 'desktop': return this.MonitorIcon;
      case 'mobile': return this.SmartphoneIcon;
      case 'phone': return this.SmartphoneIcon;
      case 'tablet': return this.SmartphoneIcon;
      case 'printer': return this.PrinterIcon;
      case 'router': return this.RouterIcon;
      case 'server': return this.ServerIcon;
      case 'iot': return this.LightbulbIcon;
      default: return this.ServerIcon;
    }
  }

  startEdit(asset: any) {
    this.editingIp = asset.ip;
    this.editNameValue = asset.custom_name || asset.hostname;
  }

  cancelEdit() {
    this.editingIp = null;
  }

  saveEdit(asset: any) {
    this.api.updateAsset(asset.ip, { custom_name: this.editNameValue }).subscribe({
      next: () => {
        asset.custom_name = this.editNameValue;
        this.editingIp = null;
      },
      error: (err) => {
        console.error('Failed to update asset name:', err);
        alert('Failed to update name. Please try again.');
        this.editingIp = null;
      }
    });
  }

  toggleTrusted(asset: any) {
    const newVal = !asset.trusted;
    this.api.setAssetTrusted(asset.ip, newVal).subscribe({
      next: () => {
        asset.trusted = newVal;
        if (newVal) asset.threat_flagged = false;
      },
      error: (err) => console.error('Failed to update trusted flag:', err)
    });
  }

  formatLastSeen(ts: number) {
    if (!ts) return 'Never';
    return new Date(ts * 1000).toLocaleString();
  }

  getRoleClass(role: string): string {
    if (!role) return '';
    const r = role.toLowerCase();
    if (r.includes('server'))   return 'role-server';
    if (r.includes('gateway') || r.includes('router')) return 'role-network';
    if (r.includes('workstation')) return 'role-workstation';
    if (r.includes('iot'))      return 'role-iot';
    if (r.includes('database')) return 'role-database';
    return 'role-default';
  }

  getCriticalityClass(score: number): string {
    if (score >= 70) return 'crit-high';
    if (score >= 40) return 'crit-medium';
    return 'crit-low';
  }

  selectAsset(asset: any) {
    this.selectedAsset = asset;
  }

  closeDrawer() {
    this.selectedAsset = null;
  }

  handleFocus(ip: string) {
    // If we wanted to link to the map focus mode, we could use the Router.
    // For now, in assets page, it could just be an alert or redirect.
  }
}
