import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { driver } from 'driver.js';
import 'driver.js/dist/driver.css';

@Injectable({
  providedIn: 'root'
})
export class TourService {
  private driverInstance: any;
  private driverLoaded = false;

  constructor(private router: Router) { }

  private async loadDriver(): Promise<void> {
    if (this.driverLoaded) return Promise.resolve();

    const style = document.createElement('style');
    style.textContent = `
      @keyframes aiPulse {
        0% { box-shadow: 0 0 0 0 rgba(105, 246, 184, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(105, 246, 184, 0); }
        100% { box-shadow: 0 0 0 0 rgba(105, 246, 184, 0); }
      }
      @keyframes aiFloat {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-3px); }
      }
      .driver-popover {
        border-radius: 12px !important;
        padding: 16px !important;
        max-width: 380px !important;
        background: #08101f !important;
        border: 1px solid rgba(105, 246, 184, 0.2) !important;
        color: #f7f9ff !important;
        box-shadow: 0 20px 40px rgba(0,0,0,0.4) !important;
      }
      .driver-popover-title {
        display: none !important;
      }
      .driver-popover-navigation-btns {
        border-top: 1px solid rgba(255,255,255,0.1) !important;
        margin-top: 12px !important;
        padding-top: 12px !important;
      }
      .driver-popover-next-btn, .driver-popover-prev-btn {
        background: #69f6b8 !important;
        color: #08101f !important;
        text-shadow: none !important;
        font-weight: 700 !important;
        border: none !important;
      }
      .driver-popover-close-btn {
        color: #8792a7 !important;
      }
    `;
    document.head.appendChild(style);
    this.driverLoaded = true;
  }

  private getStepHtml(title: string, desc: string): string {
    return `
      <div style="display: flex; gap: 16px; align-items: flex-start; font-family: 'Inter', system-ui, sans-serif;">
        <div style="flex-shrink: 0; position: relative; animation: aiFloat 3s ease-in-out infinite;">
          <div style="width: 42px; height: 42px; border-radius: 50%; background: radial-gradient(circle at 30% 30%, #a7fbe0, #69f6b8 40%, #059669); border: 2px solid #08101f; animation: aiPulse 2s infinite;"></div>
          <div style="position: absolute; inset: 6px; border-radius: 50%; border: 1px solid rgba(255,255,255,0.8); opacity: 0.5;"></div>
        </div>
        <div>
          <h3 style="margin: 0 0 6px 0; font-size: 15px; font-weight: 800; color: #69f6b8; line-height: 1.2;">${title}</h3>
          <p style="margin: 0; font-size: 13px; color: #c6cede; line-height: 1.6; font-weight: 400;">${desc}</p>
        </div>
      </div>
    `;
  }

  async startTour() {
    try {
      await this.loadDriver();
    } catch (e) {
      console.error('Failed to load interactive tour:', e);
      alert('Could not load the interactive tour. Please check your connection or ad-blocker.');
      return;
    }

    this.driverInstance = driver({
      showProgress: true,
      animate: true,
      allowClose: true,
      doneBtnText: 'Finish',
      nextBtnText: 'Next',
      prevBtnText: 'Back',
      onDestroyed: () => {
        window.scrollTo(0, 0);
        document.body.scrollTop = 0;
        document.documentElement.scrollTop = 0;
        document.querySelectorAll('.overflow-auto, .overflow-hidden, main, .flex-1').forEach(el => {
          (el as HTMLElement).scrollTop = 0;
        });
      },
      onNextClick: (elem: any, step: any, options: any) => {
        const i = options.state.activeIndex;
        if (i === 1) {
          this.router.navigate(['/analyst/dashboard']).then(() => setTimeout(() => this.driverInstance.moveNext(), 400));
        } else if (i === 3) {
          this.router.navigate(['/analyst/alerts']).then(() => setTimeout(() => this.driverInstance.moveNext(), 400));
        } else if (i === 4) {
          this.router.navigate(['/analyst/evidence']).then(() => setTimeout(() => this.driverInstance.moveNext(), 400));
        } else if (i === 5) {
          this.router.navigate(['/analyst/ai-activity']).then(() => setTimeout(() => this.driverInstance.moveNext(), 400));
        } else {
          this.driverInstance.moveNext();
        }
      },
      onPrevClick: (elem: any, step: any, options: any) => {
        const i = options.state.activeIndex;
        if (i === 4) {
          this.router.navigate(['/analyst/dashboard']).then(() => setTimeout(() => this.driverInstance.movePrevious(), 400));
        } else if (i === 5) {
          this.router.navigate(['/analyst/alerts']).then(() => setTimeout(() => this.driverInstance.movePrevious(), 400));
        } else if (i === 6) {
          this.router.navigate(['/analyst/evidence']).then(() => setTimeout(() => this.driverInstance.movePrevious(), 400));
        } else {
          this.driverInstance.movePrevious();
        }
      },
      steps: [
        {
          popover: {
            description: this.getStepHtml('Welcome to NDR!', 'I am ARIA, your AI guide. This sidebar on the left contains your main navigation.'),
          }
        },
        {
          element: '.search-wrap',
          popover: {
            description: this.getStepHtml('Global Search', 'Use this omnibar to quickly hunt for IPs, hashes, or system health.'),
            side: 'bottom',
            align: 'start'
          }
        },
        {
          element: '.metric-danger',
          popover: {
            description: this.getStepHtml('Critical Alerts Metric', 'Welcome to the Dashboard! This card tracks the most severe threats.'),
            side: 'bottom',
            align: 'center'
          }
        },
        {
          element: '.chart-frame',
          popover: {
            description: this.getStepHtml('Live Event Stream', 'This chart streams telemetry directly from the backend sensors in real-time.'),
            side: 'top',
            align: 'start'
          }
        },
        {
          element: '.alerts-table-wrap',
          popover: {
            description: this.getStepHtml('Detection Console', 'Welcome to Alerts! This table displays all correlated threats.'),
            side: 'top',
            align: 'start'
          }
        },
        {
          element: '.bundle-list',
          popover: {
            description: this.getStepHtml('Forensic Bundles', 'Welcome to Evidence! This list groups related network activity into forensic bundles.'),
            side: 'right',
            align: 'start'
          }
        },
        {
          element: '.aria-wrapper',
          popover: {
            description: this.getStepHtml('AI Activity & ARIA', 'This is my home! I watch your network 24/7. I can autonomously investigate alerts.'),
            side: 'left',
            align: 'start'
          }
        },
        {
          popover: {
            description: this.getStepHtml('You are ready!', 'You have completed the guided tour. Start hunting for threats and keeping the network safe!'),
          }
        }
      ]
    });

    this.driverInstance.drive();
  }
}
