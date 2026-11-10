/** Labels and formatting shared by the analyst's and the tenant admin's insight pages. */
export const InsightText = {
  workload(w: string): string {
    return w === 'overload' ? 'Very high' : w === 'high' ? 'High' : 'Normal';
  },
  workloadClass(w: string): string {
    return w === 'overload' ? 'text-rose-300' : w === 'high' ? 'text-amber-300' : 'text-emerald-300';
  },
  trust(t: string): string {
    return t === 'over_reliance' ? 'Relies on AI a lot'
      : t === 'under_use' ? 'Rarely uses AI suggestions'
      : t === 'calibrated' ? 'Balanced'
      : 'Not enough data yet';
  },
  trustClass(t: string): string {
    return t === 'over_reliance' ? 'text-amber-300' : t === 'under_use' ? 'text-sky-300' : t === 'calibrated' ? 'text-emerald-300' : 'text-slate-400';
  },
  depth(d: string): string {
    return d === 'brief' ? 'Brief' : d === 'detailed' ? 'Detailed' : 'Standard';
  },
  pct(part: number, whole: number): string {
    return whole ? `${Math.round((100 * part) / whole)}%` : '—';
  },
  ago(ts: number): string {
    if (!ts) return '—';
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  },
};
