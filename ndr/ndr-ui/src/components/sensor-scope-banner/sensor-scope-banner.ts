import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Radio } from 'lucide-angular';

@Component({
  selector: 'app-sensor-scope-banner',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './sensor-scope-banner.html',
  styleUrl: './sensor-scope-banner.css',
})
export class SensorScopeBanner {
  @Input() sensorIds: string[] = [];

  RadioIcon = Radio;

  get hasSensors(): boolean {
    return this.sensorIds && this.sensorIds.length > 0;
  }
}