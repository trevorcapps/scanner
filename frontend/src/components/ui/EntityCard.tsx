import type { ReactNode } from 'react';
import { StatusDot } from './primitives';

export function EntityCard({
  title,
  meta,
  status,
  lines,
  actions,
}: {
  title: string;
  meta?: string;
  status?: string;
  lines?: ReactNode[];
  actions?: ReactNode;
}) {
  return (
    <div className="panel flex flex-col gap-2 p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm font-semibold text-text">{title}</div>
          {meta && <div className="mt-0.5 truncate text-2xs text-muted">{meta}</div>}
        </div>
        {status && <StatusDot status={status} />}
      </div>
      {lines?.filter(Boolean).map((l, i) => (
        <div key={i} className="text-2xs text-text-soft">
          {l}
        </div>
      ))}
      {actions && <div className="mt-1 flex flex-wrap gap-1.5">{actions}</div>}
    </div>
  );
}
