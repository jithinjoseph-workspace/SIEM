import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule } from 'lucide-angular';
import { SetupBase } from '../../shared/setup/setup-base';

@Component({
  selector: 'app-setup',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './setup.html',
  styleUrl: './setup.css',
})
export class Setup extends SetupBase {
  protected readonly unauthorizedRedirectPath = '/analyst/dashboard';
}
