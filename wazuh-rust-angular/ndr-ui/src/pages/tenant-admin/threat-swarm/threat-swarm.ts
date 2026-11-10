import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Share2, Eye } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { SwarmText } from '../../siem-ai/swarm/swarm-text';

/**
 * Threat Swarm (tenant admin): whether this tenant takes part in the federated
 * threat swarm (off / receive only / share and receive), and exactly what would
 * be shared (siem-api /api/v1/swarm/tenant, /preview).
 */
@Component({
  selector: 'app-threat-swarm',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './threat-swarm.html',
})
export class ThreatSwarm implements OnInit {
  private siem = inject(SiemService);

  ShareIcon = Share2;
  EyeIcon = Eye;
  t = SwarmText;

  status = signal<any>(null);
  preview = signal<any>(null);
  saving = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  levels: { value: 'off' | 'receive' | 'share'; label: string; text: string }[] = [
    { value: 'off', label: 'Off', text: 'Nothing is sent or received.' },
    { value: 'receive', label: 'Receive only', text: 'Your alerts are checked against what other organisations reported. Nothing about you is sent.' },
    { value: 'share', label: 'Share and receive', text: 'Also send anonymous fingerprints of attacks on you, so others are protected sooner.' },
  ];

  ngOnInit() {
    this.load();
  }

  load() {
    this.siem.getSwarmStatus().subscribe({ next: s => this.status.set(s), error: () => this.error.set('The threat swarm is not available.') });
  }

  set(level: 'off' | 'receive' | 'share') {
    this.saving.set(true);
    this.siem.setSwarmLevel(level).subscribe({
      next: () => { this.saving.set(false); this.message.set('Saved. It applies from the next swarm round (every 15 minutes).'); setTimeout(() => this.message.set(null), 4000); this.load(); },
      error: e => { this.saving.set(false); this.error.set(e?.error?.message || 'Could not save.'); },
    });
  }

  showPreview() {
    this.siem.getSwarmPreview().subscribe({ next: p => this.preview.set(p), error: e => this.error.set(e?.error?.message || 'Preview not available.') });
  }
}
