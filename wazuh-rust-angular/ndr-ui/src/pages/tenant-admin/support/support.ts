import { Component, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule } from 'lucide-angular';
import { SupportBase } from '../../shared/support/support-base';

@Component({
  selector: 'app-tenant-support',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: '../../shared/support/support.html',
  styleUrl: './support.css',
})
export class TenantSupport extends SupportBase {}
