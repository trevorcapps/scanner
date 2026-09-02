import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { Pagination, UnifiedVuln } from '@/types';

export interface VulnQuery {
  search?: string;
  source?: string;
  has_exploit?: boolean;
  severity?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}

interface VulnPage {
  vulnerabilities: UnifiedVuln[];
  pagination: Pagination;
  summary: {
    unique_cves: number;
    with_exploits: number;
    affected_hosts: number;
    by_severity: Record<string, number>;
    by_source: Record<string, number>;
  };
  filtered_total: number;
}

export function useVulnList(params: VulnQuery) {
  return useQuery({
    queryKey: ['vulns', params],
    queryFn: () =>
      api.get<VulnPage>(`/api/v1/vulnerabilities${qs({ ...params, page: params.page ?? 1 })}`),
    placeholderData: keepPreviousData,
  });
}

export function useVuln(id: string | null) {
  return useQuery({
    queryKey: ['vuln', id],
    queryFn: () => api.get<{ vulnerability: UnifiedVuln }>(`/api/v1/vulnerabilities/${encodeURIComponent(id!)}`),
    enabled: !!id,
  });
}
