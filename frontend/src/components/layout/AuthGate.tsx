import { useEffect, useState, type ReactNode } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { setUnauthorizedHandler } from '@/lib/api';
import { Spinner } from '@/components/ui/primitives';
import { useQueryClient } from '@tanstack/react-query';

export function AuthGate({ children }: { children: ReactNode }) {
  const { user, setupMode, isLoading, isError } = useAuth();
  const qc = useQueryClient();

  useEffect(() => {
    setUnauthorizedHandler(() => {
      qc.setQueryData(['auth', 'me'], { user: undefined });
      qc.invalidateQueries({ queryKey: ['auth', 'me'] });
    });
  }, [qc]);

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (setupMode) return <AuthForm mode="setup" />;
  if (isError || !user) return <AuthForm mode="login" />;
  return <>{children}</>;
}

function AuthForm({ mode }: { mode: 'login' | 'setup' }) {
  const { login, setup } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'setup') await setup(username, password);
      else await login(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-bg px-4">
      <form onSubmit={submit} className="panel w-full max-w-sm p-6 shadow-panel">
        <div className="mb-1 font-mono text-lg font-semibold tracking-tight">ARTEMIS</div>
        <p className="eyebrow mb-6">
          {mode === 'setup' ? 'Create the initial administrator' : 'Authenticate to continue'}
        </p>

        <label className="eyebrow mb-1 block">Username</label>
        <input
          className="input mb-3"
          value={username}
          autoFocus
          autoComplete="username"
          onChange={(e) => setUsername(e.target.value)}
        />
        <label className="eyebrow mb-1 block">Password</label>
        <input
          className="input mb-4"
          type="password"
          value={password}
          autoComplete={mode === 'setup' ? 'new-password' : 'current-password'}
          onChange={(e) => setPassword(e.target.value)}
        />

        {error && <div className="mb-3 text-2xs text-danger">{error}</div>}
        {mode === 'setup' && (
          <div className="mb-3 text-2xs text-muted">Password must be at least 8 characters.</div>
        )}

        <button className="btn-primary w-full py-2" disabled={busy}>
          {busy ? '…' : mode === 'setup' ? 'Create admin' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
