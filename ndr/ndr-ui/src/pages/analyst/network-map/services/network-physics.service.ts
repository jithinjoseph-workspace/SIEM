import { Injectable, NgZone } from '@angular/core';
import * as d3 from 'd3';

@Injectable({
  providedIn: 'root'
})
export class NetworkPhysicsService {
  private simulation: any;

  constructor(private zone: NgZone) {}

  initSimulation(nodes: any[], edges: any[], width: number, height: number, onTick: () => void) {
    if (this.simulation) {
      this.simulation.stop();
    }

    // d3's internal timer drives ticks via requestAnimationFrame, which
    // zone.js patches — start it outside Angular's zone so each tick (the
    // caller's onTick does raw SVG attr updates, not template bindings)
    // doesn't trigger an app-wide change-detection pass.
    this.zone.runOutsideAngular(() => {
      this.simulation = d3
        .forceSimulation(nodes)
        .alphaDecay(0.04)
        .force(
          'link',
          d3
            .forceLink(edges)
            .id((d: any) => d.id)
            .distance((d: any) => {
              const w = Math.log((d.connections || 1) + 1);
              return Math.max(120, 240 - w * 15);
            })
        )
        .force('charge', d3.forceManyBody().strength((d: any) => (d.is_internal ? -1200 : -600)))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide(65).iterations(2));

      this.simulation.on('tick', onTick);
    });
    return this.simulation;
  }

  /**
   * Hot-update an existing simulation with new nodes/edges.
   * Old nodes keep their x/y — only new nodes scatter from their seeded position.
   * This avoids the full restart that causes the entire graph to reshuffle.
   */
  updateSimulation(nodes: any[], edges: any[], onTick: () => void) {
    if (!this.simulation) return;

    this.simulation.stop();
    this.simulation.nodes(nodes);
    (this.simulation.force('link') as d3.ForceLink<any, any>).links(edges);
    this.simulation.on('tick', onTick);
    // A low alpha heat-up so only the new nodes settle — old nodes barely move
    this.zone.runOutsideAngular(() => {
      this.simulation.alpha(0.25).alphaTarget(0).restart();
    });
  }

  get dragBehavior() {
    return d3
      .drag<SVGGElement, any>()
      .on('start', (event, d: any) => {
        if (!event.active && this.simulation) {
          this.zone.runOutsideAngular(() => this.simulation.alphaTarget(0.3).restart());
        }
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d: any) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d: any) => {
        if (!event.active && this.simulation) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });
  }

  destroy() {
    if (this.simulation) {
      this.simulation.stop();
      this.simulation = null;
    }
  }
}
