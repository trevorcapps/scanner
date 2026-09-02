import { clsx } from 'clsx';
import type { ReactNode, HTMLAttributes } from 'react';

export function Eyebrow({ children }: { children: ReactNode }) {
  return <span className="eyebrow">{children}</span>;
}

export function PageHeading({
  eyebrow,
  title,
  state,
  actions,
}: {
  eyebrow: string;
  title: string;
  state?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1 className="mt-1 text-xl font-semibold tracking-tight text-text">{title}</h1>
      </div>
      <div className="flex items-center gap-3">
        {actions}
        {state && <span className="eyebrow flex items-center gap-1.5">{state}</span>}
      </div>
    </div>
  );
}

export function Panel({
  title,
  meta,
  children,
  className,
  bodyClassName,
  actions,
}: {
  title?: string;
  meta?: string;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  actions?: ReactNode;
}) {
  return (
    <section className={clsx('panel flex flex-col overflow-hidden shadow-panel', className)}>
      {title && (
        <header className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
          <h2 className="font-mono text-2xs uppercase tracking-[0.16em] text-text-soft">
            {title}
            {meta && <span className="ml-2 text-faint">{meta}</span>}
          </h2>
          {actions}
        </header>
      )}
      <div className={clsx('flex-1', bodyClassName ?? 'p-4')}>{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: 'critical' | 'high' | 'medium' | 'default';
  hint?: string;
}) {
  const toneClass =
    tone === 'critical'
      ? 'text-danger'
      : tone === 'high'
        ? 'text-amber'
        : tone === 'medium'
          ? 'text-blue'
          : 'text-text';
  return (
    <div className="panel px-4 py-3">
      <div className={clsx('data text-2xl font-semibold', toneClass)}>{value}</div>
      <div className="eyebrow mt-1">{label}</div>
      {hint && <div className="mt-0.5 text-2xs text-faint">{hint}</div>}
    </div>
  );
}

export function StatusDot({ status }: { status?: string | null }) {
  const color =
    status === 'active' || status === 'success' || status === 'healthy'
      ? 'rgb(var(--lime))'
      : status === 'stale' || status === 'running' || status === 'queued' || status === 'retrying'
        ? 'rgb(var(--amber))'
        : status === 'failed' || status === 'offline'
          ? 'rgb(var(--danger))'
          : 'rgb(var(--muted))';
  return (
    <span
      className="inline-block h-2 w-2 shrink-0 rounded-full"
      style={{ background: color }}
      title={status ?? undefined}
    />
  );
}

export function SeverityPill({ severity, score }: { severity: string; score?: number | null }) {
  const map: Record<string, string> = {
    critical: 'border-danger/40 bg-danger/10 text-danger',
    high: 'border-amber/40 bg-amber/10 text-amber',
    medium: 'border-blue/40 bg-blue/10 text-blue',
    low: 'border-cyan/40 bg-cyan/10 text-cyan',
    info: 'border-line bg-hover text-muted',
  };
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-2xs uppercase tracking-wide',
        map[severity] ?? map.info,
      )}
    >
      {severity}
      {score != null && <span className="opacity-70">{score.toFixed(1)}</span>}
    </span>
  );
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border border-line bg-hover px-1.5 py-0.5 font-mono text-2xs uppercase tracking-wide text-text-soft',
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <div
      className={clsx(
        'h-5 w-5 animate-spin rounded-full border-2 border-line border-t-blue',
        className,
      )}
    />
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center text-sm text-muted">
      {children}
    </div>
  );
}

export function Skeleton(props: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={clsx('animate-pulse rounded bg-hover', props.className)} />;
}
