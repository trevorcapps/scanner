import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type {
  CvssDistribution,
  DashboardSummary,
  RiskHeatmap,
  ScanQueue,
  Topology,
  TopVuln,
  Trends,
} from '@/types';

const opts = { staleTime: 20_000 };

export const useSummary = () =>
  useQuery({ queryKey: ['dash', 'summary'], queryFn: () => api.get<DashboardSummary>('/api/v1/dashboard/summary'), ...opts });

export const useCvss = () =>
  useQuery({ queryKey: ['dash', 'cvss'], queryFn: () => api.get<CvssDistribution>('/api/v1/dashboard/cvss-distribution'), ...opts });

export const useTopVulns = (limit = 10) =>
  useQuery({
    queryKey: ['dash', 'top', limit],
    queryFn: () => api.get<{ vulnerabilities: TopVuln[] }>(`/api/v1/dashboard/top-vulnerabilities?limit=${limit}`),
    ...opts,
  });

export const useHeatmap = () =>
  useQuery({ queryKey: ['dash', 'heatmap'], queryFn: () => api.get<RiskHeatmap>('/api/v1/dashboard/risk-heatmap'), ...opts });

export const useTrends = (days = 30) =>
  useQuery({ queryKey: ['dash', 'trends', days], queryFn: () => api.get<Trends>(`/api/v1/dashboard/trends?days=${days}`), ...opts });

export const useTopology = () =>
  useQuery({ queryKey: ['dash', 'topology'], queryFn: () => api.get<Topology>('/api/v1/dashboard/topology'), staleTime: 60_000 });

export const useScanQueue = () =>
  useQuery({
    queryKey: ['dash', 'queue'],
    queryFn: () => api.get<ScanQueue>('/api/v1/dashboard/scan-queue'),
    refetchInterval: 10_000,
  });
