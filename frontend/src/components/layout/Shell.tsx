import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { clsx } from 'clsx';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { LogPanel } from './LogPanel';
import { connectSocket } from '@/lib/socket';

export function Shell() {
  const [mobileNav, setMobileNav] = useState(false);

  useEffect(() => {
    connectSocket();
  }, []);

  return (
    <div className="flex h-full w-full overflow-hidden bg-bg">
      {/* Desktop sidebar */}
      <div className="hidden lg:block">
        <Sidebar />
      </div>

      {/* Mobile drawer */}
      {mobileNav && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={() => setMobileNav(false)} />
          <div className="relative h-full w-52">
            <Sidebar onNavigate={() => setMobileNav(false)} />
          </div>
        </div>
      )}

      <div className={clsx('flex min-w-0 flex-1 flex-col')}>
        <TopBar onMenu={() => setMobileNav(true)} />
        <main className="flex-1 overflow-y-auto p-4 sm:p-6">
          <Outlet />
        </main>
        <LogPanel />
      </div>
    </div>
  );
}
