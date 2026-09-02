import { clsx } from 'clsx';
import { NavLink } from 'react-router-dom';
import { useUi } from '@/stores/ui';

interface Item {
  to: string;
  label: string;
  meta: string;
}

const NAV: Item[] = [
  { to: '/', label: 'Overview', meta: 'LIVE' },
  { to: '/scan', label: 'New trace', meta: 'RUN' },
  { to: '/assets', label: 'Assets', meta: 'HOST' },
  { to: '/vulnerabilities', label: 'Findings', meta: 'CVE' },
  { to: '/sites', label: 'Sites', meta: 'SCOPE' },
  { to: '/schedules', label: 'Schedules', meta: 'AUTO' },
  { to: '/agents', label: 'Agents', meta: 'EDR' },
  { to: '/settings', label: 'Control', meta: 'CFG' },
  { to: '/data-query', label: 'Data query', meta: 'SQL' },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const collapsed = useUi((s) => s.sidebarCollapsed);

  return (
    <nav
      className={clsx(
        'flex h-full flex-col border-r border-line bg-surface transition-[width]',
        collapsed ? 'w-14' : 'w-52',
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-line px-4">
        <span className="font-mono text-sm font-bold tracking-tight">
          {collapsed ? 'A' : 'ARTEMIS'}
        </span>
      </div>

      <ul className="flex-1 overflow-y-auto py-3">
        {NAV.map((it) => (
          <li key={it.to}>
            <NavLink
              to={it.to}
              end={it.to === '/'}
              onClick={onNavigate}
              className={({ isActive }) =>
                clsx(
                  'group flex items-center justify-between border-l-2 px-4 py-1.5 text-xs',
                  isActive
                    ? 'border-blue bg-hover text-text'
                    : 'border-transparent text-text-soft hover:bg-hover hover:text-text',
                )
              }
            >
              <span className="truncate">{it.label}</span>
              {!collapsed && <span className="font-mono text-2xs text-faint">{it.meta}</span>}
            </NavLink>
          </li>
        ))}
      </ul>

      <a
        href="/classic"
        className="border-t border-line-soft px-4 py-2 font-mono text-2xs uppercase tracking-wider text-faint hover:text-text-soft"
      >
        {collapsed ? '↗' : 'Classic UI ↗'}
      </a>
      <button
        className="border-t border-line px-4 py-2 text-left font-mono text-2xs uppercase tracking-wider text-muted hover:text-text"
        onClick={() => useUi.getState().toggleSidebar()}
      >
        {collapsed ? '»' : '« Collapse'}
      </button>
    </nav>
  );
}
