import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  ChevronDown, ChevronRight, Edit, RefreshCw, Search, Trash2, UserPlus, X,
  ShieldCheck, Clock, Users as LucideUsers, Layers, Zap, Building2, CheckCircle2, AlertTriangle,
  Shield, KeyRound, Mail, User, ChevronLeft, ArrowUpDown
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-users',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class Users implements OnInit {
  Math = Math;

  ChevronDownIcon    = ChevronDown;
  ChevronRightIcon   = ChevronRight;
  EditIcon           = Edit;
  RefreshIcon        = RefreshCw;
  SearchIcon         = Search;
  TrashIcon          = Trash2;
  UserPlusIcon       = UserPlus;
  XIcon              = X;
  ShieldCheckIcon    = ShieldCheck;
  ClockIcon          = Clock;
  UsersIcon          = LucideUsers;
  LayersIcon         = Layers;
  ZapIcon            = Zap;
  Building2Icon      = Building2;
  CheckCircle2Icon   = CheckCircle2;
  AlertTriangleIcon  = AlertTriangle;
  ShieldIcon         = Shield;
  KeyRoundIcon       = KeyRound;
  MailIcon           = Mail;
  UserIcon           = User;
  ChevronLeftIcon    = ChevronLeft;
  ArrowUpDownIcon    = ArrowUpDown;

  currentUser: any = {};

  users: any[]    = [];
  tenants: any[]  = [];
  loadingUsers    = false;
  showAddUser     = false;
  userSearch      = '';
  selectedTenant  = 'all';
  selectedRoleFilter: 'all' | 'admin' | 'tenant_admin' | 'analyst' | 'disabled' = 'all';
  pendingDeleteUser: any = null;
  editingUser: any       = null;

  newUser = { username: '', password: '', role: 'tenant_admin', tenant_id: '', gmail: '' };
  userForm = { role: 'tenant_admin', tenant_id: '', active: true, password: '', permissions: '' };

  roleOptions = [
    { value: 'tenant_admin',   label: 'Tenant Admin' },
    { value: 'default_user',   label: 'Default User' },
    { value: 'admin',          label: 'Platform Admin' },
    { value: 'senior_analyst', label: 'Senior Analyst' },
    { value: 'analyst',        label: 'Analyst' },
    { value: 'viewer',         label: 'Viewer' },
  ];
  createUserRoleOptions = [
    { value: 'tenant_admin', label: 'Tenant Admin' },
    { value: 'default_user', label: 'Default User' },
  ];
  readonly usernamePattern = /^[A-Za-z0-9._-]+$/;
  savingUser  = false;
  msg         = '';
  msgType     = '';
  collapsedTenants = new Set<string>();

  constructor(
    private api: Api,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
    public clock: ClockService,
  ) {}

  ngOnInit() {
    this.currentUser = this.auth.getUser();
    this.loadUsers();
    this.loadTenants();
  }

  loadUsers() {
    this.loadingUsers = true;
    this.api.getUsers().subscribe({
      next: (data: any) => { this.users = data.users || []; this.loadingUsers = false; this.cdr.detectChanges(); },
      error: () => { this.loadingUsers = false; this.showMsg('Failed to load users', 'error'); this.cdr.detectChanges(); },
    });
  }

  loadTenants() {
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants = data.tenants || []; this.cdr.detectChanges(); },
      error: reportRxjsError,
    });
  }

  get totalUsersCount() { return this.users.length; }
  get activeUsersCount() { return this.users.filter(u => u.active !== false && !this.isTenantInactive(u.tenant_id)).length; }
  get superAdminCount() { return this.users.filter(u => u.role === 'super_admin' || u.role === 'admin').length; }
  get tenantAdminCount() { return this.users.filter(u => u.role === 'tenant_admin').length; }
  get analystCount() { return this.users.filter(u => u.role === 'analyst' || u.role === 'senior_analyst').length; }
  get disabledCount() { return this.users.filter(u => u.active === false || this.isTenantInactive(u.tenant_id)).length; }
  get activePercent() { return this.users.length ? Math.round((this.activeUsersCount / this.users.length) * 100) : 100; }

  get otherRolesCount() {
    return Math.max(0, this.totalUsersCount - this.superAdminCount - this.tenantAdminCount - this.analystCount);
  }

  get adminPercent() {
    return this.totalUsersCount ? Math.round((this.superAdminCount / this.totalUsersCount) * 100) : 0;
  }

  get tenantAdminPercent() {
    return this.totalUsersCount ? Math.round((this.tenantAdminCount / this.totalUsersCount) * 100) : 0;
  }

  get analystPercent() {
    return this.totalUsersCount ? Math.round((this.analystCount / this.totalUsersCount) * 100) : 0;
  }

  get otherPercent() {
    return Math.max(0, 100 - this.adminPercent - this.tenantAdminPercent - this.analystPercent);
  }

  get managedUsers()      { return this.users; }
  get tenantAdmins()      { return this.users.filter(u => u.role === 'tenant_admin'); }

  // View Mode & Pagination (Tenant Cards with Member Rosters)
  viewMode: 'grouped' | 'cards' | 'flat' = 'grouped';
  tenantsPerPage: number = 3;
  currentTenantPage: number = 1;
  flatUsersPerPage: number = 10;
  currentFlatPage: number = 1;

  get allFilteredUsers() {
    const query = this.userSearch.trim().toLowerCase();
    return this.users.filter(u => {
      const matchesTenant = this.selectedTenant === 'all' || u.tenant_id === this.selectedTenant;
      const matchesQuery  = !query || 
        u.username?.toLowerCase().includes(query) || 
        u.role?.toLowerCase().includes(query) || 
        u.tenant_id?.toLowerCase().includes(query) ||
        (u.gmail && u.gmail.toLowerCase().includes(query));
      
      let matchesRole = true;
      if (this.selectedRoleFilter === 'admin') {
        matchesRole = u.role === 'admin' || u.role === 'super_admin';
      } else if (this.selectedRoleFilter === 'tenant_admin') {
        matchesRole = u.role === 'tenant_admin';
      } else if (this.selectedRoleFilter === 'analyst') {
        matchesRole = u.role === 'analyst' || u.role === 'senior_analyst';
      } else if (this.selectedRoleFilter === 'disabled') {
        matchesRole = u.active === false || this.isTenantInactive(u.tenant_id);
      }
      return matchesTenant && matchesQuery && matchesRole;
    });
  }

  get filteredTenantAdmins() {
    return this.allFilteredUsers;
  }

  get allUsersByTenant(): { tenantId: string; tenantName: string; isActive: boolean; users: any[] }[] {
    const groups = new Map<string, any[]>();
    for (const u of this.allFilteredUsers) {
      const tid = u.tenant_id || 'default';
      if (!groups.has(tid)) groups.set(tid, []);
      groups.get(tid)!.push(u);
    }
    return Array.from(groups.entries()).map(([tenantId, users]) => {
      const tenant = this.tenants.find(t => t.id === tenantId);
      return { 
        tenantId, 
        tenantName: tenant?.name ?? (tenantId === 'default' ? 'Default Organization' : tenantId), 
        isActive: tenant?.active ?? true, 
        users 
      };
    });
  }

  get totalTenantPages(): number {
    return Math.max(1, Math.ceil(this.allUsersByTenant.length / this.tenantsPerPage));
  }

  get usersByTenant(): { tenantId: string; tenantName: string; isActive: boolean; users: any[] }[] {
    const start = (this.currentTenantPage - 1) * this.tenantsPerPage;
    return this.allUsersByTenant.slice(start, start + this.tenantsPerPage);
  }

  get pagedFlatUsers(): any[] {
    const start = (this.currentFlatPage - 1) * this.flatUsersPerPage;
    return this.allFilteredUsers.slice(start, start + this.flatUsersPerPage);
  }

  get totalFlatPages(): number {
    return Math.max(1, Math.ceil(this.allFilteredUsers.length / this.flatUsersPerPage));
  }

  setRoleFilter(role: 'all' | 'admin' | 'tenant_admin' | 'analyst' | 'disabled') {
    this.selectedRoleFilter = role;
    this.currentTenantPage = 1;
    this.currentFlatPage = 1;
    this.cdr.detectChanges();
  }

  onFilterChange() {
    this.currentTenantPage = 1;
    this.currentFlatPage = 1;
    this.cdr.detectChanges();
  }

  setTenantsPerPage(count: number) {
    this.tenantsPerPage = count;
    this.currentTenantPage = 1;
    this.cdr.detectChanges();
  }

  setFlatUsersPerPage(count: number) {
    this.flatUsersPerPage = count;
    this.currentFlatPage = 1;
    this.cdr.detectChanges();
  }

  nextTenantPage() {
    if (this.currentTenantPage < this.totalTenantPages) {
      this.currentTenantPage++;
      this.cdr.detectChanges();
    }
  }

  prevTenantPage() {
    if (this.currentTenantPage > 1) {
      this.currentTenantPage--;
      this.cdr.detectChanges();
    }
  }

  nextFlatPage() {
    if (this.currentFlatPage < this.totalFlatPages) {
      this.currentFlatPage++;
      this.cdr.detectChanges();
    }
  }

  prevFlatPage() {
    if (this.currentFlatPage > 1) {
      this.currentFlatPage--;
      this.cdr.detectChanges();
    }
  }

  setViewMode(mode: 'flat' | 'grouped' | 'cards') {
    this.viewMode = mode;
    this.cdr.detectChanges();
  }

  getPermissionsCount(user: any): string {
    if (user.role === 'super_admin' || user.role === 'admin') return 'Full Platform Scope';
    if (!user.permissions) return 'Standard Access';
    const perms = user.permissions.split(',').filter((p: string) => p.trim().length > 0);
    return perms.length > 0 ? `${perms.length} Permissions` : 'Standard Access';
  }

  getUserAvatarClass(user: any): string {
    if (user.role === 'super_admin' || user.role === 'admin') return 'avatar--super-admin';
    if (user.role === 'tenant_admin') return 'avatar--tenant-admin';
    if (user.role === 'analyst' || user.role === 'senior_analyst') return 'avatar--analyst';
    return 'avatar--default';
  }

  toggleTenantGroup(tenantId: string) {
    if (this.collapsedTenants.has(tenantId)) this.collapsedTenants.delete(tenantId);
    else this.collapsedTenants.add(tenantId);
  }

  isGroupCollapsed(tenantId: string) { return this.collapsedTenants.has(tenantId); }

  get selectedTenantName() { return this.selectedTenant === 'all' ? 'All tenants' : this.tenantName(this.selectedTenant); }
  get selectedTenantIsInactive() { return this.selectedTenant !== 'all' && this.isTenantInactive(this.selectedTenant); }

  tenantName(id: string)       { return this.tenants.find(t => t.id === id)?.name || id; }
  isTenantInactive(id: string) { return this.tenants.find(t => t.id === id)?.active === false; }
  tenantUserCount(id: string)  { return this.users.filter(u => u.tenant_id === id).length; }

  blockedUserCount(tenantId: string) {
    return this.isTenantInactive(tenantId)
      ? this.users.filter(u => u.tenant_id === tenantId && u.active !== false).length
      : 0;
  }

  userStatusLabel(user: any) {
    if (user.active === false) return 'Disabled';
    if (this.isTenantInactive(user.tenant_id)) return 'Blocked by tenant';
    return 'Active';
  }

  userStatusClass(user: any) {
    return user.active === false || this.isTenantInactive(user.tenant_id) ? 'inactive' : 'active';
  }

  roleLabel(role: string) { return this.roleOptions.find(o => o.value === role)?.label || role; }
  getRolePillClass(role: string): string { return 'role-' + (role || '').replace(/_/g, '-'); }

  isCurrentSuperAdmin(user: any) { return user?.role === 'super_admin' && user?.username === this.currentUser?.username; }
  usernameExists(username: string) { return this.users.some(u => u.username?.trim().toLowerCase() === username.trim().toLowerCase()); }

  // Validation
  private validateUsername(username: string, checkUnique: boolean) {
    const v = username.trim();
    if (!v) return 'Username is required';
    if (v.length < 3) return 'Username must be at least 3 characters';
    if (v.length > 50) return 'Username must be 50 characters or less';
    if (!this.usernamePattern.test(v)) return 'Username can use letters, numbers, dot, underscore, and hyphen only';
    if (checkUnique && this.usernameExists(v)) return 'Username already exists';
    return '';
  }

  private validatePassword(password: string, username: string, required: boolean) {
    const v = password || '';
    const errors: string[] = [];
    if (!v) { if (required) errors.push('Password is required'); return errors; }
    if (v.length < 8) errors.push('Password must be at least 8 characters');
    if (!/[A-Z]/.test(v)) errors.push('Password needs an uppercase letter');
    if (!/[a-z]/.test(v)) errors.push('Password needs a lowercase letter');
    if (!/[0-9]/.test(v)) errors.push('Password needs a number');
    if (!/[^A-Za-z0-9]/.test(v)) errors.push('Password needs a special character');
    if (username.trim() && v.toLowerCase() === username.trim().toLowerCase()) errors.push('Password cannot be the same as username');
    return errors;
  }

  private validateRole(role: string) {
    if (!role) return 'Role is required';
    return this.roleOptions.some(o => o.value === role) ? '' : 'Select a valid role';
  }

  private validateUserTenant(role: string, tenantId: string) {
    if (role === 'tenant_admin' && !tenantId) return 'Tenant is required for tenant admin';
    if (role === 'tenant_admin' && tenantId === 'default') return 'Tenant admin cannot be assigned to default';
    if (role === 'default_user' && tenantId !== 'default') return 'Default user must use the default tenant';
    return '';
  }

  private defaultPermissionsFor(role: string) {
    switch (role) {
      case 'tenant_admin':   return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,health,users';
      case 'admin':          return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup';
      case 'default_user':   return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,setup';
      case 'senior_analyst': return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,health';
      case 'analyst':        return 'dashboard,alerts,logs,live,network-map,intel,health';
      default:               return 'dashboard,alerts,health';
    }
  }

  private applyRoleTenantRules(user: { role: string; tenant_id: string }) {
    if (user.role === 'default_user') user.tenant_id = 'default';
    else if (user.role !== 'tenant_admin' && !user.tenant_id) user.tenant_id = 'default';
    else if (user.role === 'tenant_admin' && user.tenant_id === 'default') user.tenant_id = '';
  }

  get newUserUsernameError()  { return this.validateUsername(this.newUser.username, true); }
  get newUserPasswordErrors() { return this.validatePassword(this.newUser.password, this.newUser.username, true); }
  get newUserRoleError()      { return this.validateRole(this.newUser.role); }
  get newUserTenantError()    { return this.validateUserTenant(this.newUser.role, this.newUser.tenant_id); }
  get canCreateUser() {
    return !this.newUserUsernameError && this.newUserPasswordErrors.length === 0 && !this.newUserRoleError && !this.newUserTenantError;
  }

  get editUserPasswordErrors() { return this.validatePassword(this.userForm.password, this.editingUser?.username || '', false); }
  get editUserRoleError()      { return this.validateRole(this.userForm.role); }
  get editUserTenantError()    { return this.validateUserTenant(this.userForm.role, this.userForm.tenant_id); }
  get canSaveUserEdit() {
    return !!this.editingUser && !this.editUserRoleError && !this.editUserTenantError &&
      this.editUserPasswordErrors.length === 0 && !this.isCurrentSuperAdmin(this.editingUser);
  }

  private firstNewUserValidationError() {
    return this.newUserUsernameError || this.newUserPasswordErrors[0] || this.newUserRoleError || this.newUserTenantError || 'Fix user form validation errors';
  }

  private firstEditUserValidationError() {
    return this.editUserRoleError || this.editUserTenantError || this.editUserPasswordErrors[0] || 'Fix user form validation errors';
  }

  onNewUserRoleChange()  { this.applyRoleTenantRules(this.newUser); }
  onEditUserRoleChange() { this.applyRoleTenantRules(this.userForm); this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role); }

  addUser() {
    this.applyRoleTenantRules(this.newUser);
    if (!this.canCreateUser) { this.showMsg(this.firstNewUserValidationError(), 'error'); return; }
    if (!this.newUser.username || !this.newUser.password) { this.showMsg('Username and password required', 'error'); return; }
    if (this.newUser.role === 'tenant_admin' && (!this.newUser.tenant_id || this.newUser.tenant_id === 'default')) {
      this.showMsg('Select a tenant for the tenant admin', 'error'); return;
    }

    this.savingUser = true;
    this.api.createUser({ ...this.newUser, tenant_id: this.newUser.tenant_id || 'default' }).subscribe({
      next: (data: any) => {
        this.savingUser = false;
        if (data.status === 'ok') {
          this.showAddUser = false;
          this.newUser = { username: '', password: '', role: 'tenant_admin', tenant_id: '', gmail: '' };
          this.loadUsers();
          this.showMsg('User created', 'success');
        } else {
          this.showMsg(data.message, 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => { this.savingUser = false; this.showMsg('Failed to create user', 'error'); this.cdr.detectChanges(); },
    });
  }

  requestDeleteUser(user: any) {
    if (this.isCurrentSuperAdmin(user)) { this.showMsg('Current super admin cannot be deleted', 'error'); return; }
    this.pendingDeleteUser = user;
  }

  cancelDeleteUser()  { this.pendingDeleteUser = null; }

  confirmDeleteUser() {
    if (!this.pendingDeleteUser) return;
    this.api.deleteUser(this.pendingDeleteUser.id).subscribe({
      next: () => { this.pendingDeleteUser = null; this.loadUsers(); this.showMsg('User deleted', 'success'); this.cdr.detectChanges(); },
      error: () => { this.showMsg('Failed to delete user', 'error'); this.cdr.detectChanges(); },
    });
  }

  openEditUser(user: any) {
    if (this.isCurrentSuperAdmin(user)) { this.showMsg('Current super admin cannot be edited', 'error'); return; }
    this.editingUser = user;
    this.userForm = {
      role: user.role, tenant_id: user.tenant_id, active: user.active !== false,
      password: '', permissions: user.permissions || this.defaultPermissionsFor(user.role),
    };
  }

  closeEditUser() { this.editingUser = null; }

  saveUserEdit() {
    if (!this.editingUser) return;
    if (this.isCurrentSuperAdmin(this.editingUser)) { this.showMsg('Current super admin cannot be edited', 'error'); return; }
    this.applyRoleTenantRules(this.userForm);
    if (!this.canSaveUserEdit) { this.showMsg(this.firstEditUserValidationError(), 'error'); return; }
    if (this.userForm.role === 'tenant_admin' && this.userForm.tenant_id === 'default') {
      this.showMsg('Tenant admin must be assigned to a tenant', 'error'); return;
    }

    this.api.updateUser(this.editingUser.id, {
      role: this.userForm.role, tenant_id: this.userForm.tenant_id || 'default',
      active: this.userForm.active, password: this.userForm.password, permissions: this.userForm.permissions,
    }).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') { this.editingUser = null; this.loadUsers(); this.showMsg('User updated', 'success'); }
        else { this.showMsg(data.message || 'Failed to update user', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to update user', 'error'); this.cdr.detectChanges(); },
    });
  }

  setUserActive(user: any, active: boolean) {
    if (this.isCurrentSuperAdmin(user)) { this.showMsg('Current super admin cannot be deactivated', 'error'); return; }
    const previous = user.active;
    user.active = active;
    this.cdr.detectChanges();

    this.api.setUserStatus(user.id, active).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(active ? 'User activated' : 'User deactivated', 'success');
          this.reloadUsersWithRetry(user.id, active);
        } else {
          user.active = previous;
          this.showMsg(data.message || 'Failed to update user status', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => { user.active = previous; this.showMsg('Failed to update user status', 'error'); this.cdr.detectChanges(); },
    });
  }

  private reloadUsersWithRetry(userId: string, expectedActive: boolean, attempt = 0): void {
    const delays = [1000, 2000, 4000];
    setTimeout(() => {
      this.api.getUsers().subscribe({
        next: (data: any) => {
          const fresh: any[] = data.users || [];
          const target = fresh.find((u: any) => u.id === userId);
          if (target && target.active !== expectedActive && attempt < delays.length - 1) {
            this.reloadUsersWithRetry(userId, expectedActive, attempt + 1);
          } else { this.users = fresh; this.cdr.detectChanges(); }
        },
        error: reportRxjsError,
      });
    }, delays[attempt] ?? delays[delays.length - 1]);
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
