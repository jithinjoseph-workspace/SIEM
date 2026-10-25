/** Shared labels for the threat swarm pages. */
export const SwarmText = {
  kind(k: string): string {
    return k === 'external_ip' ? 'Attacker IP' : k === 'file_hash' ? 'Malicious file' : k === 'technique_chain' ? 'Attack technique chain' : k;
  },
  severity(s: number): string {
    return ['Low', 'Medium', 'High', 'Critical'][s] ?? '—';
  },
  severityClass(s: number): string {
    return s >= 3 ? 'text-rose-300' : s === 2 ? 'text-orange-300' : s === 1 ? 'text-amber-300' : 'text-slate-300';
  },
  day(d: number): string {
    return d ? new Date(d * 86400000).toLocaleDateString() : '—';
  },
  when(ts: number): string {
    return ts ? new Date(ts * 1000).toLocaleString() : 'never';
  },
};
