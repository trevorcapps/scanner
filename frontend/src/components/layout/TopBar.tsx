import { useUi } from '@/stores/ui';
import { useAuth } from '@/hooks/useAuth';
import { CommandPalette } from '@/components/CommandPalette';
import { useEffect, useState } from 'react';

export function TopBar({ onMenu }: { onMenu: () => void }) {
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const logOpen = useUi((s) => s.logOpen);
  const setLogOpen = useUi((s) => s.setLogOpen);
  const { user, logout } = useAuth();
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface px-4">
      <button className="btn px-2 py-1 lg:hidden" onClick={onMenu} aria-label="Menu">
        ☰
      </button>

      <button
        className="btn flex-1 justify-start px-3 py-1.5 text-muted lg:max-w-md"
        onClick={() => setPaletteOpen(true)}
      >
        Search assets & findings
        <span className="ml-auto hidden font-mono text-2xs text-faint sm:inline">⌘K</span>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <button
          className="btn px-2 py-1"
          onClick={() => setLogOpen(!logOpen)}
          title="Activity log"
        >
          {logOpen ? 'Log ▾' : 'Log ▸'}
        </button>
        <button className="btn px-2 py-1" onClick={toggleTheme} title="Theme">
          {theme === 'dark' ? '◐' : '◑'}
        </button>
        {user && (
          <div className="flex items-center gap-2">
            <div className="hidden text-right sm:block">
              <div className="font-mono text-2xs text-text">{user.display_name || user.username}</div>
              <div className="eyebrow">{user.role}</div>
            </div>
            <button className="btn px-2 py-1" onClick={logout} title="Sign out">
              ⏻
            </button>
          </div>
        )}
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </header>
  );
}
