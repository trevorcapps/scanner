import { StatusDot } from '@/components/ui/primitives';
import { relativeTime } from '@/lib/format';
import type { ScanQueue } from '@/types';

export function ScanQueuePanel({ data }: { data: ScanQueue }) {
  const entries = Object.entries(data.counts).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3">
        {entries.length === 0 && <span className="text-2xs text-faint">No jobs yet</span>}
        {entries.map(([status, n]) => (
          <div key={status} className="flex items-center gap-1.5 font-mono text-2xs">
            <StatusDot status={status} />
            <span className="text-text-soft">{status}</span>
            <span className="text-text">{n}</span>
          </div>
        ))}
      </div>
      <ul className="divide-y divide-line-soft">
        {data.recent.slice(0, 6).map((j) => (
          <li key={j.id} className="flex items-center gap-2 py-1.5 text-xs">
            <StatusDot status={j.status} />
            <span className="data truncate text-text">{j.target}</span>
            <span className="text-2xs text-muted">{j.job_type.replace('_', ' ')}</span>
            <span className="ml-auto shrink-0 font-mono text-2xs text-faint">
              {relativeTime(j.created_at)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
