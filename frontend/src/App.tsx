import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AuthGate } from '@/components/layout/AuthGate';
import { Shell } from '@/components/layout/Shell';
import { Spinner } from '@/components/ui/primitives';
import { Toaster } from '@/components/Toaster';

const Dashboard = lazy(() => import('@/pages/Dashboard'));
const Assets = lazy(() => import('@/pages/Assets'));
const Vulns = lazy(() => import('@/pages/Vulns'));

function Loading() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner className="h-6 w-6" />
    </div>
  );
}

export function App() {
  return (
    <AuthGate>
      <Toaster />
      <Routes>
        <Route element={<Shell />}>
          <Route
            path="/"
            element={
              <Suspense fallback={<Loading />}>
                <Dashboard />
              </Suspense>
            }
          />
          <Route
            path="/assets"
            element={
              <Suspense fallback={<Loading />}>
                <Assets />
              </Suspense>
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <Suspense fallback={<Loading />}>
                <Vulns />
              </Suspense>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthGate>
  );
}
