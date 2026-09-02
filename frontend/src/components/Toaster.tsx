import { clsx } from 'clsx';
import { useToasts } from '@/stores/toast';

export function Toaster() {
  const { toasts, dismiss } = useToasts();
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[80] flex flex-col gap-2">
      {toasts.map((t) => (
        <button
          key={t.id}
          onClick={() => dismiss(t.id)}
          className={clsx(
            'pointer-events-auto min-w-56 max-w-sm rounded border px-3 py-2 text-left font-mono text-2xs shadow-panel',
            t.tone === 'error'
              ? 'border-danger/50 bg-danger-bg text-danger'
              : t.tone === 'success'
                ? 'border-lime/40 bg-lime/10 text-lime'
                : 'border-line bg-raised text-text-soft',
          )}
        >
          {t.message}
        </button>
      ))}
    </div>
  );
}
