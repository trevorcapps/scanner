import { Suspense, lazy, type ComponentType } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AuthGate } from '@/components/layout/AuthGate';
import { Shell } from '@/components/layout/Shell';
import { Spinner } from '@/components/ui/primitives';
import { Toaster } from '@/components/Toaster';

const Dashboard = lazy(() => import('@/pages/Dashboard'));
const Assets = lazy(() => import('@/pages/Assets'));
const Vulns = lazy(() => import('@/pages/Vulns'));
const Scan = lazy(() => import('@/pages/Scan'));
const Sites = lazy(() => import('@/pages/Sites'));
const Schedules = lazy(() => import('@/pages/Schedules'));
const Agents = lazy(() => import('@/pages/Agents'));
const Settings = lazy(() => import('@/pages/Settings'));
const DataQuery = lazy(() => import('@/pages/DataQuery'));

function Loading() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner className="h-6 w-6" />
    </div>
  );
}

function page(C: ComponentType) {
  return (
    <Suspense fallback={<Loading />}>
      <C />
    </Suspense>
  );
}

export function App() {
  return (
    <AuthGate>
      <Toaster />
      <Routes>
        <Route element={<Shell />}>
          <Route path="/" element={page(Dashboard)} />
          <Route path="/assets" element={page(Assets)} />
          <Route path="/vulnerabilities" element={page(Vulns)} />
          <Route path="/scan" element={page(Scan)} />
          <Route path="/sites" element={page(Sites)} />
          <Route path="/schedules" element={page(Schedules)} />
          <Route path="/agents" element={page(Agents)} />
          <Route path="/settings" element={page(Settings)} />
          <Route path="/data-query" element={page(DataQuery)} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthGate>
  );
}
