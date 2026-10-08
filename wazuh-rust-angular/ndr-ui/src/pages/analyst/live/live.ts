import { Component, OnInit, OnDestroy, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Websocket } from '../../../services/websocket/websocket';
import { LucideAngularModule, Radio, Zap, Activity, ShieldAlert, Wifi } from 'lucide-angular';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-live',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './live.html',
  styleUrl: './live.css'
})
export class Live implements OnInit, OnDestroy {
  messages: any[] = [];
  eventCount: number = 0;
  hitCount: number = 0;
  autoScroll: boolean = true;

  RadioIcon = Radio;
  ZapIcon = Zap;
  ActivityIcon = Activity;
  ShieldIcon = ShieldAlert;
  WifiIcon = Wifi;

  @ViewChild('streamContainer') streamContainer!: ElementRef;

  private subs: Subscription[] = [];
  private updateScheduled = false;

  private scheduleUpdate() {
    if (this.updateScheduled) return;
    this.updateScheduled = true;
    setTimeout(() => {
      this.cdr.detectChanges();
      this.updateScheduled = false;
    }, 0);
  }

  constructor(private ws: Websocket, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.subs.push(
      this.ws.messages$.subscribe(msg => {
        if (msg.type === 'agent_status' || msg.type === 'interfaces') return;

        let entry: any = {
          timestamp: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          src: msg.src || '',
          dst: msg.dst || '',
          proto: (msg.proto || '').toUpperCase(),
          raw: msg,
        };

        if (msg.type === 'agent-z') {
          entry.kind = 'zeek';
          entry.label = 'AGENT-Z';
          entry.event_type = (msg.service || msg.conn_state || 'conn').toUpperCase();
          entry.extra = msg.conn_state || '';
          this.eventCount++;
        } else if (msg.type === 'agent-s') {
          entry.kind = 'suricata';
          entry.label = 'AGENT-S';
          entry.event_type = (msg.event_type || 'flow').toUpperCase();
          entry.extra = '';
          this.eventCount++;
        } else if (msg.type === 'hit') {
          entry.kind = 'hit';
          entry.label = 'HIT';
          entry.event_type = (msg.severity || 'medium').toUpperCase();
          entry.extra = msg.tags?.join(' · ') || '';
          entry.score = msg.score != null ? Math.round(msg.score) : null;
          entry.cid = msg.cid || '';
          this.hitCount++;
        } else if (msg.type === 'alert') {
          entry.kind = 'alert';
          entry.label = 'ALERT';
          entry.event_type = 'ALERT';
          entry.extra = msg.description || msg.rule || 'Rule triggered';
          this.hitCount++;
        } else {
          return;
        }

        this.messages.unshift(entry);
        if (this.messages.length > 100) this.messages.pop();
        this.scheduleUpdate();

        if (this.autoScroll && this.streamContainer) {
          this.streamContainer.nativeElement.scrollTop = 0;
        }
      })
    );
  }

  getEventBadgeClass(entry: any): string {
    const t = (entry.event_type || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    return `evt-badge evt-${t}`;
  }

  clearMessages() {
    this.messages = [];
    this.eventCount = 0;
    this.hitCount = 0;
    this.cdr.detectChanges();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
