import { clsx } from 'clsx';
import { NavLink } from 'react-router-dom';
import { useUi } from '@/stores/ui';

interface Item {
  to: string;
  label: string;
  meta: string;
  external?: boolean;
}

const NATIVE: Item[] = [
  { to: '/', label: 'Overview', meta: 'LIVE' },
  { to: '/assets', label: 'Assets', meta: 'HOST' },
  { to: '/vulnerabilities', label: 'Findings', meta: 'CVE' },
];

const CLASSIC: Item[] = [
  { to: '/classic#page-scan', label: 'New trace', meta: 'RUN', external: true },
  { to: '/classic#page-sites', label: 'Sites', meta: 'SCOPE', external: true },
  { to: '/classic#page-schedules', label: 'Schedules', meta: 'AUTO', external: true },
  { to: '/classic#page-agents', label: 'Agents', meta: 'EDR', external: true },
  { to: '/classic#page-settings', label: 'Control', meta: 'CFG', external: true },
  { to: '/classic#page-sql', label: 'Data query', meta: 'SQL', external: true },
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

      <div className="flex-1 overflow-y-auto py-3">
        <Section label={collapsed ? '' : 'Console'} items={NATIVE} collapsed={collapsed} onNavigate={onNavigate} />
        <div className="my-3 border-t border-line-soft" />
        <Section label={collapsed ? '' : 'Classic'} items={CLASSIC} collapsed={collapsed} onNavigate={onNavigate} />
      </div>

      <button
        className="border-t border-line px-4 py-2 text-left font-mono text-2xs uppercase tracking-wider text-muted hover:text-text"
        onClick={() => useUi.getState().toggleSidebar()}
      >
        {collapsed ? '»' : '« Collapse'}
      </button>
    </nav>
  );
}

function Section({
  label,
  items,
  collapsed,
  onNavigate,
}: {
  label: string;
  items: Item[];
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  return (
    <div>
      {label && <div className="eyebrow px-4 pb-1.5">{label}</div>}
      <ul>
        {items.map((it) =>
          it.external ? (
            <li key={it.to}>
              <a
                href={it.to}
                className="group flex items-center justify-between px-4 py-1.5 text-xs text-text-soft hover:bg-hover hover:text-text"
              >
                <span className="truncate">{it.label}</span>
                {!collapsed && <span className="font-mono text-2xs text-faint">{it.meta}↗</span>}
              </a>
            </li>
          ) : (
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
          ),
        )}
      </ul>
    </div>
  );
}
