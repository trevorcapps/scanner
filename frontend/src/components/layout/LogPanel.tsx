import { useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { getSocket } from '@/lib/socket';
import { useUi } from '@/stores/ui';

interface LogLine {
  ts: string;
  message: string;
  level: string;
}

const MAX = 500;

export function LogPanel() {
  const open = useUi((s) => s.logOpen);
  const setLogOpen = useUi((s) => s.setLogOpen);
  const [lines, setLines] = useState<LogLine[]>([]);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const s = getSocket();
    const onLog = (data: { message: string; level?: string }) => {
      setLines((prev) => {
        const next = [
          ...prev,
          {
            ts: new Date().toLocaleTimeString(),
            message: data.message,
            level: data.level || 'info',
          },
        ];
        return next.length > MAX ? next.slice(next.length - MAX) : next;
      });
    };
    s.on('scan_log', onLog);
    return () => {
      s.off('scan_log', onLog);
    };
  }, []);

  useEffect(() => {
    if (open && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [lines, open]);

  if (!open) return null;

  return (
    <div className="flex h-56 shrink-0 flex-col border-t border-line bg-surface">
      <div className="flex items-center justify-between border-b border-line-soft px-4 py-1.5">
        <span className="eyebrow">Activity log</span>
        <div className="flex gap-1">
          <button className="btn px-2 py-0.5" onClick={() => setLines([])}>
            Clear
          </button>
          <button className="btn px-2 py-0.5" onClick={() => setLogOpen(false)}>
            Hide
          </button>
        </div>
      </div>
      <div ref={bodyRef} className="flex-1 overflow-y-auto px-4 py-2 font-mono text-2xs leading-relaxed">
        {lines.length === 0 && <div className="text-faint">Waiting for scan activity…</div>}
        {lines.map((l, i) => (
          <div key={i} className="flex gap-2">
            <span className="shrink-0 text-faint">{l.ts}</span>
            <span
              className={clsx(
                'break-all',
                l.level === 'error' && 'text-danger',
                l.level === 'warning' && 'text-amber',
                l.level === 'success' && 'text-lime',
                l.level === 'debug' && 'text-muted',
              )}
            >
              {l.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
