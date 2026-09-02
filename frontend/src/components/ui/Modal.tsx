import { useEffect, type ReactNode } from 'react';
import { clsx } from 'clsx';

export function Modal({
  open,
  onClose,
  title,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto p-4 pt-16">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className={clsx(
          'panel relative w-full shadow-2xl',
          wide ? 'max-w-2xl' : 'max-w-md',
        )}
      >
        <header className="flex items-center justify-between border-b border-line-soft px-5 py-3">
          <h2 className="font-mono text-sm font-semibold text-text">{title}</h2>
          <button className="btn px-2 py-1" onClick={onClose}>
            Esc
          </button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="mb-3 block">
      <span className="eyebrow mb-1 block">{label}</span>
      {children}
      {hint && <span className="mt-0.5 block text-2xs text-faint">{hint}</span>}
    </label>
  );
}

export function FormActions({ children }: { children: ReactNode }) {
  return <div className="mt-5 flex items-center justify-end gap-2">{children}</div>;
}
