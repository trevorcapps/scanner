import { useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { User } from '@/types';

interface MeResponse {
  user?: User;
  setup_mode?: boolean;
}

export function useAuth() {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: () => api.get<MeResponse>('/api/v1/auth/me'),
    retry: false,
    staleTime: 60_000,
  });

  const login = useCallback(
    async (username: string, password: string) => {
      await api.post('/api/v1/auth/login', { username, password });
      await qc.invalidateQueries({ queryKey: ['auth', 'me'] });
    },
    [qc],
  );

  const setup = useCallback(
    async (username: string, password: string) => {
      await api.post('/api/v1/auth/setup', { username, password });
      await qc.invalidateQueries({ queryKey: ['auth', 'me'] });
    },
    [qc],
  );

  const logout = useCallback(async () => {
    await api.post('/api/v1/auth/logout');
    qc.clear();
    window.location.href = '/';
  }, [qc]);

  return {
    user: query.data?.user ?? null,
    setupMode: query.data?.setup_mode ?? false,
    isLoading: query.isLoading,
    isError: query.isError,
    refetch: query.refetch,
    login,
    setup,
    logout,
  };
}
