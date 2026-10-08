import { Component, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { Websocket } from '../../services/websocket/websocket';
import { Api } from '../../services/api/api';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.html',
  styleUrl: './login.css'
})
export class Login {
  username = '';
  password = '';
  loading = false;
  error = '';
  showPassword = false;

  // ── Forgot Password Modal ────────────────────────────────────────────────
  showForgotModal = false;
  forgotStep = 1; // 1: Secret, 2: Gmail, 3: OTP, 4: Success
  forgotLoading = false;
  forgotError = '';

  // ── Forced password reset (default installer password still in use) ──────
  showForceReset = false;
  forceResetNewPassword = '';
  forceResetConfirmPassword = '';
  forceResetError = '';
  forceResetLoading = false;
  private pendingUser: any = null;

  forgotData = {
    username: '',
    secretCode: '',
    gmailHint: '',
    gmail: '',
    otp: '',
    newPassword: '',
    confirmPassword: ''
  };

  constructor(
    private auth: AuthService,
    private api: Api,
    private router: Router,
    private cdr: ChangeDetectorRef,
    private ws: Websocket
  ) {
    if (this.auth.isLoggedIn()) {
      this.router.navigate([this.auth.getDefaultRoute()]);
    }
  }

  // ── Forgot Password Methods ──────────────────────────────────────────────

  openForgotModal() {
    this.showForgotModal = true;
    this.forgotStep = 1;
    this.forgotError = '';
    this.forgotData = {
      username: this.username,
      secretCode: '',
      gmailHint: '',
      gmail: '',
      otp: '',
      newPassword: '',
      confirmPassword: ''
    };
  }

  closeForgotModal() {
    this.showForgotModal = false;
  }

  submitSecretCode() {
    if (!this.forgotData.username || !this.forgotData.secretCode) {
      this.forgotError = 'Username and Secret Code are required';
      return;
    }
    this.forgotLoading = true;
    this.forgotError = '';
    this.api.forgotVerifySecret(this.forgotData.username, this.forgotData.secretCode).subscribe({
      next: (res: any) => {
        this.forgotLoading = false;
        if (res.status === 'ok') {
          this.forgotData.gmailHint = res.gmail_hint;
          this.forgotStep = 2;
        } else {
          this.forgotError = res.message || 'Verification failed';
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.forgotLoading = false;
        this.forgotError = err.error?.message || 'Verification failed';
        this.cdr.detectChanges();
      }
    });
  }

  submitGmail() {
    if (!this.forgotData.gmail) {
      this.forgotError = 'Email address is required';
      return;
    }
    this.forgotLoading = true;
    this.forgotError = '';
    this.api.forgotSendOtp(this.forgotData.username, this.forgotData.gmail).subscribe({
      next: (res: any) => {
        this.forgotLoading = false;
        if (res.status === 'ok') {
          this.forgotStep = 3;
        } else {
          this.forgotError = res.message || 'Failed to send OTP';
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.forgotLoading = false;
        this.forgotError = err.error?.message || 'Failed to send OTP';
        this.cdr.detectChanges();
      }
    });
  }

  submitOtp() {
    if (!this.forgotData.otp || !this.forgotData.newPassword) {
      this.forgotError = 'All fields are required';
      return;
    }
    if (this.forgotData.newPassword !== this.forgotData.confirmPassword) {
      this.forgotError = 'Passwords do not match';
      return;
    }
    this.forgotLoading = true;
    this.forgotError = '';
    this.api.forgotResetPassword(
      this.forgotData.username,
      this.forgotData.otp,
      this.forgotData.newPassword
    ).subscribe({
      next: (res: any) => {
        this.forgotLoading = false;
        if (res.status === 'ok') {
          this.forgotStep = 4;
        } else {
          this.forgotError = res.message || 'Password reset failed';
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.forgotLoading = false;
        this.forgotError = err.error?.message || 'Password reset failed';
        this.cdr.detectChanges();
      }
    });
  }

  login() {
    if (!this.username || !this.password) {
      this.error = 'Please enter username and password';
      return;
    }
    this.loading = true;
    this.error = '';
    this.cdr.detectChanges();

    this.auth.login(this.username, this.password).subscribe({
      next: (res: any) => {
        this.loading = false;
        if (res.status === 'ok' && res.user) {
          if (res.user.must_reset_password) {
            // Backend already issued a real session — the account just still
            // has the default installer password. Don't navigate yet: force
            // a real password before letting them into the app.
            this.pendingUser = res.user;
            this.showForceReset = true;
            this.forceResetError = '';
            this.forceResetNewPassword = '';
            this.forceResetConfirmPassword = '';
          } else {
            this.completeLogin(res.user);
          }
        } else {
          // status: "error" returned with 200 OK (should not happen now, but fallback)
          this.error = res.message || 'Login failed';
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        // HTTP 403 = account disabled by administrator
        if (err.status === 403) {
          this.error = err.error?.message ||
            'Your account has been disabled. Please contact your administrator.';
        } else if (err.status === 401) {
          this.error = 'Invalid username or password';
        } else {
          this.error = err.error?.message ||
            'Login failed. Please try again.';
        }
        this.cdr.detectChanges();
      }
    });
  }

  /** Explicit, intentional skip — the account keeps the default password
   *  and will be prompted again on the next login. */
  closeForceReset() {
    this.showForceReset = false;
    const user = this.pendingUser;
    this.pendingUser = null;
    if (user) this.completeLogin(user);
  }

  private completeLogin(user: any) {
    const role = user?.role;
    if (role === 'admin' || role === 'super_admin') {
      this.router.navigate(['/admin']).then(() => this.ws.connect());
    } else if (role === 'tenant_admin') {
      this.router.navigate(['/tenant-admin']).then(() => this.ws.connect());
    } else {
      this.router.navigate([this.auth.getDefaultRoute()]).then(() => this.ws.connect());
    }
  }

  // ── Forced password reset ────────────────────────────────────────────────

  submitForceReset() {
    const newPassword = this.forceResetNewPassword;
    if (!newPassword || newPassword !== this.forceResetConfirmPassword) {
      this.forceResetError = 'Passwords do not match';
      return;
    }
    if (newPassword === this.password) {
      this.forceResetError = 'Choose a password different from the default one';
      return;
    }
    this.forceResetLoading = true;
    this.forceResetError = '';
    this.api.selfResetPassword(
      this.username,
      this.pendingUser?.tenant_id || '',
      this.password,
      newPassword
    ).subscribe({
      next: (res: any) => {
        this.forceResetLoading = false;
        if (res.status === 'ok') {
          this.showForceReset = false;
          const user = this.pendingUser;
          this.pendingUser = null;
          this.password = newPassword;
          this.completeLogin(user);
        } else {
          this.forceResetError = res.message || 'Failed to update password';
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.forceResetLoading = false;
        this.forceResetError = err.error?.message || 'Failed to update password';
        this.cdr.detectChanges();
      }
    });
  }
}

