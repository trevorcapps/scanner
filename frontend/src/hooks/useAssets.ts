import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { AssetDetail, AssetSummary, Pagination } from '@/types';

export interface AssetQuery {
  q?: string;
  device_type?: string;
  severity?: string;
  has_vulns?: boolean;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}

interface AssetPage {
  assets: AssetSummary[];
  pagination: Pagination;
}

export function useAssetList(params: AssetQuery) {
  return useQuery({
    queryKey: ['assets', params],
    queryFn: () =>
      api.get<AssetPage>(`/api/v1/assets${qs({ ...params, page: params.page ?? 1 })}`),
    placeholderData: keepPreviousData,
  });
}

export function useAsset(ip: string | null) {
  return useQuery({
    queryKey: ['asset', ip],
    queryFn: () => api.get<{ asset: AssetDetail }>(`/api/v1/assets/${ip}`),
    enabled: !!ip,
  });
}

export function useAssetActions(ip: string) {
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['assets'] });
    qc.invalidateQueries({ queryKey: ['asset', ip] });
    qc.invalidateQueries({ queryKey: ['dash'] });
  };

  const scan = useMutation({
    mutationFn: (arg: string | { scan_type: string; options?: Record<string, unknown> }) => {
      const { scan_type, options } = typeof arg === 'string' ? { scan_type: arg, options: undefined } : arg;
      return api.post<{ id: string }>('/api/v1/scans', { target: ip, scan_type, options });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dash', 'queue'] });
      qc.invalidateQueries({ queryKey: ['auth-details', ip] });
    },
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/assets/${ip}`),
    onSuccess: invalidate,
  });

  const reclassify = useMutation({
    mutationFn: () => api.post(`/api/v1/asset/${ip}/reclassify`),
    onSuccess: invalidate,
  });

  return { scan, remove, reclassify };
}
