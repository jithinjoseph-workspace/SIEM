import { Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { Api } from '../../../../services/api/api';

export interface GraphData {
  nodes: any[];
  edges: any[];
  nodeCount: number;
  edgeCount: number;
}

@Injectable({
  providedIn: 'root'
})
export class NetworkDataService {
  constructor(private api: Api) {}

  private calculateConnections(nodes: any[], edges: any[]) {
    nodes.forEach((n: any) => {
      n.connections = edges
        .filter((e: any) => e.source === n.id || e.target === n.id)
        .reduce((sum: number, e: any) => sum + e.connections, 0);
    });
  }

  loadMap(limit: number = 25): Observable<GraphData> {
    return this.api.getNetworkMap('top', limit).pipe(
      map((data: any) => {
        const nodes = data.nodes || [];
        const edges = data.edges || [];
        this.calculateConnections(nodes, edges);
        
        return {
          nodes,
          edges,
          nodeCount: data.total_nodes ?? nodes.length,
          edgeCount: data.total_edges ?? edges.length
        };
      })
    );
  }

  loadFocusMode(ip: string): Observable<GraphData> {
    return this.api.getNetworkMapNode(ip).pipe(
      map((data: any) => {
        const nodes = data.nodes || [];
        const edges = data.edges || [];
        this.calculateConnections(nodes, edges);

        return {
          nodes,
          edges,
          nodeCount: data.total_nodes ?? nodes.length,
          edgeCount: data.total_edges ?? edges.length
        };
      })
    );
  }

  expandCluster(clusterNode: any, currentNodes: any[], currentEdges: any[]): Observable<GraphData> {
    return this.api.getNetworkMap().pipe(
      map((data: any) => {
        const fullNodes = data.nodes || [];
        const fullEdges = data.edges || [];
        
        // Find unclustered nodes belonging to this cluster
        const newNodes = fullNodes.filter((n: any) => clusterNode.member_ips.includes(n.id));
        
        // Remove cluster node
        const updatedNodes = currentNodes.filter((n: any) => n.id !== clusterNode.id);
        
        // Add new nodes with initial cluster coordinates
        newNodes.forEach((n: any) => {
          if (!updatedNodes.find((ext: any) => ext.id === n.id)) {
            n.x = clusterNode.x || 0;
            n.y = clusterNode.y || 0;
            updatedNodes.push(n);
          }
        });

        // Re-evaluate valid edges
        const currentIds = new Set(updatedNodes.map(n => n.id));
        const validEdges = fullEdges.filter((e: any) => currentIds.has(e.source) && currentIds.has(e.target));

        this.calculateConnections(updatedNodes, validEdges);

        return {
          nodes: updatedNodes,
          edges: validEdges,
          nodeCount: updatedNodes.length, // approximation
          edgeCount: validEdges.length
        };
      })
    );
  }
}
