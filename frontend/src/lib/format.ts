export function formatDate(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value.includes('T') || value.includes(' ') ? value : `${value}T00:00:00`);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function relativeTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value.includes('T') || value.includes(' ') ? value : `${value}T00:00:00Z`);
  const diff = Date.now() - d.getTime();
  if (Number.isNaN(diff)) return value;
  const s = Math.round(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'rgb(var(--danger))',
  high: 'rgb(var(--amber))',
  medium: 'rgb(var(--blue))',
  low: 'rgb(var(--cyan))',
  info: 'rgb(var(--muted))',
};

export function severityRank(s?: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s ?? 'info'] ?? 5;
}

export function compactNumber(n: number): string {
  return Intl.NumberFormat(undefined, { notation: 'compact' }).format(n);
}
