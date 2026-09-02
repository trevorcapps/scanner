import { create } from 'zustand';
import { persist } from 'zustand/middleware';

type Theme = 'dark' | 'light';

export interface ScanDefaults {
  ports: string;
  scanSpeed: string;
  hostTimeout: number;
  maxHosts: number;
  vulscan: boolean;
  vulnTimeout: number;
  severity: string;
  rateLimit: number;
  templates: string;
}

export const DEFAULT_SCAN: ScanDefaults = {
  ports: '',
  scanSpeed: 'T3',
  hostTimeout: 300,
  maxHosts: 256,
  vulscan: false,
  vulnTimeout: 600,
  severity: 'critical,high,medium,low',
  rateLimit: 150,
  templates: '',
};

interface UiState {
  theme: Theme;
  sidebarCollapsed: boolean;
  logOpen: boolean;
  scanDefaults: ScanDefaults;
  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
  toggleSidebar: () => void;
  setLogOpen: (v: boolean) => void;
  setScanDefaults: (d: ScanDefaults) => void;
}

export const useUi = create<UiState>()(
  persist(
    (set, get) => ({
      theme: 'dark',
      sidebarCollapsed: false,
      logOpen: false,
      scanDefaults: DEFAULT_SCAN,
      setTheme: (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        set({ theme });
      },
      toggleTheme: () => get().setTheme(get().theme === 'dark' ? 'light' : 'dark'),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setLogOpen: (logOpen) => set({ logOpen }),
      setScanDefaults: (scanDefaults) => set({ scanDefaults }),
    }),
    { name: 'artemis-ui' },
  ),
);

/** Call once on boot to sync the persisted theme onto <html>. */
export function applyStoredTheme() {
  const t = useUi.getState().theme;
  document.documentElement.setAttribute('data-theme', t);
}
