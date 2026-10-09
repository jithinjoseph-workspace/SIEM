import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

interface FaqItem {
  question: string;
  answer: string;
  isOpen: boolean;
}

@Component({
  selector: 'app-faq-accordion',
  standalone: true,
  imports: [CommonModule],
  template: `
    <section class="amix-faq-section">
      <div class="faq-container">
        <div class="faq-header">
          <span class="faq-badge mono">// THREAT INTELLIGENCE & ARCHITECTURE FAQ</span>
          <h2 class="faq-title">DEFENSE DIRECTORY & KNOWLEDGE MATRIX</h2>
          <p class="faq-subtitle text-muted">Technical deep-dive into the Wazuh Rust agent, active response quarantine, and cognitive SIEM copilot.</p>
        </div>

        <div class="faq-list">
          <div
            *ngFor="let item of faqs(); let idx = index"
            class="faq-card"
            [class.active]="item.isOpen"
            (click)="toggleFaq(idx)"
          >
            <div class="faq-question-bar">
              <div class="faq-q-left">
                <span class="faq-num mono">0{{ idx + 1 }}</span>
                <span class="faq-question-text">{{ item.question }}</span>
              </div>
              <div class="faq-toggle-icon">
                <span class="icon-line horizontal"></span>
                <span class="icon-line vertical" [class.rotated]="item.isOpen"></span>
              </div>
            </div>

            <div class="faq-answer-wrap" [class.expanded]="item.isOpen">
              <div class="faq-answer-content">
                <p class="faq-answer-text">{{ item.answer }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  `,
  styleUrls: ['./faq-accordion.component.css']
})
export class FaqAccordionComponent {
  faqs = signal<FaqItem[]>([
    {
      question: 'What is the AMIX SIEM Defense Matrix, and how does it interface with Wazuh?',
      answer: 'The AMIX SIEM Defense Matrix is our next-generation threat simulation and operations showcase. It interfaces directly with the Wazuh-inspired Rust agent daemon and Tokio Axum backend server, pulling real-time telemetry from endpoints and visualizing live attack vectors, active responses, and MITRE ATT&CK tactics in an immersive 3D environment.',
      isOpen: true
    },
    {
      question: 'How does the lightweight Rust agent collect Windows Event Channels and Sysmon with low CPU?',
      answer: 'The agent leverages native Win32 EvtSubscribe and ReadDirectoryChangesW APIs compiled with zero-copy Rust bindings. It hooks directly into Windows Event Channels (Security 4624/4625/4688, Sysmon Event ID 1 process trees) and streams structured JSON directly to the Tokio engine with less than 15MB RAM and under 1.5% CPU overhead.',
      isOpen: false
    },
    {
      question: 'How does Active Response terminate ransomware and preserve volume shadow copies?',
      answer: 'The Active Response engine continuously monitors file entropy and canary decoys. When suspicious rapid mass file modification or calls to vssadmin delete shadows are detected, the agent triggers an immediate kernel process kill on the offending PID and dynamically creates Windows Firewall socket isolation rules within 400 microseconds.',
      isOpen: false
    },
    {
      question: 'How does the Neural SOC Copilot 120B analyze incidents using Groq hardware?',
      answer: 'Our AI Copilot connects to high-speed Groq LPUs running large reasoning models (such as GPT-OSS 120B and Llama 3.3). When a critical alert or simulation fires, the copilot consumes the exact JSON telemetry, evaluates the parent-child process tree, assigns confidence scores, and produces executive summaries alongside ready-to-run PowerShell/Bash remediation commands.',
      isOpen: false
    },
    {
      question: 'Can I simulate red-team attacks safely without disrupting business operations?',
      answer: 'Yes! The Attack Simulator module runs contained atomic adversary scenarios — testing password spraying, mock ransomware canary file touches, and encoded command execution — without harming underlying operating system files or risking data loss.',
      isOpen: false
    },
    {
      question: 'Can the 3D WebGL Threat Canvas be disabled for battery optimization?',
      answer: 'Absolutely. The "3D MATRIX ON/OFF" toggle switch in the fixed header cleanly pauses the Three.js WebGL requestAnimationFrame loop, allowing smooth, lightweight static execution on low-power mobile or laptop devices.',
      isOpen: false
    }
  ]);

  toggleFaq(index: number): void {
    this.faqs.update(items =>
      items.map((item, i) => {
        if (i === index) {
          return { ...item, isOpen: !item.isOpen };
        }
        return item;
      })
    );
  }
}
