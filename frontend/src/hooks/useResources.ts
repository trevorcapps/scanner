import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

/* ---- Scan profiles ---- */
export interface ScanProfile {
  id: string;
  name: string;
  icon?: string;
  description?: string;
  auth_required?: boolean;
}
export const useScanProfiles = () =>
  useQuery({
    queryKey: ['scan-profiles'],
    queryFn: () => api.get<{ profiles: ScanProfile[] }>('/api/v1/scan-profiles'),
    staleTime: 5 * 60_000,
  });

/* ---- Credentials ---- */
export interface Credential {
  id: number;
  name: string;
  cred_type: string;
  username: string;
  key_path: string;
  password_set?: boolean;
}
export function useCredentials() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.get<{ credentials: Credential[] }>('/api/v1/credentials'),
  });
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/credentials', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/api/v1/credentials/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
  return { list, save, remove };
}

/* ---- Sites ---- */
export function useSites() {
  const qc = useQueryClient();
  const inv = () => qc.invalidateQueries({ queryKey: ['sites'] });
  return {
    list: useQuery({ queryKey: ['sites'], queryFn: () => api.get<any[]>('/api/v1/sites') }),
    create: useMutation({ mutationFn: (b: any) => api.post('/api/v1/sites', b), onSuccess: inv }),
    update: useMutation({
      mutationFn: ({ id, body }: { id: number; body: any }) => api.put(`/api/v1/sites/${id}`, body),
      onSuccess: inv,
    }),
    remove: useMutation({ mutationFn: (id: number) => api.del(`/api/v1/sites/${id}`), onSuccess: inv }),
    scan: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/sites/${id}/scan`), onSuccess: inv }),
    toggle: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/sites/${id}/toggle`), onSuccess: inv }),
  };
}
export const useSite = (id: number | null) =>
  useQuery({ queryKey: ['site', id], queryFn: () => api.get<any>(`/api/v1/sites/${id}`), enabled: !!id });

/* ---- Schedules ---- */
export function useSchedules() {
  const qc = useQueryClient();
  const inv = () => qc.invalidateQueries({ queryKey: ['schedules'] });
  return {
    list: useQuery({ queryKey: ['schedules'], queryFn: () => api.get<any[]>('/api/v1/schedules') }),
    create: useMutation({ mutationFn: (b: any) => api.post('/api/v1/schedules', b), onSuccess: inv }),
    update: useMutation({
      mutationFn: ({ id, body }: { id: number; body: any }) => api.put(`/api/v1/schedules/${id}`, body),
      onSuccess: inv,
    }),
    remove: useMutation({ mutationFn: (id: number) => api.del(`/api/v1/schedules/${id}`), onSuccess: inv }),
    run: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/schedules/${id}/run`), onSuccess: inv }),
    toggle: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/schedules/${id}/toggle`), onSuccess: inv }),
  };
}
export const useScanHistory = (scheduledScanId?: number) =>
  useQuery({
    queryKey: ['scan-history', scheduledScanId ?? 'all'],
    queryFn: () =>
      api.get<any[]>(
        `/api/v1/scan-history${scheduledScanId ? `?scheduled_scan_id=${scheduledScanId}` : ''}`,
      ),
  });

/* ---- Agents ---- */
export function useAgentTelemetry() {
  return useQuery({
    queryKey: ['agent-telemetry'],
    queryFn: () => api.get<any>('/api/v1/agents/telemetry'),
    refetchInterval: 20_000,
  });
}
export const useAgent = (id: number | null) =>
  useQuery({
    queryKey: ['agent', id],
    queryFn: () => api.get<any>(`/api/v1/agents/${id}`),
    enabled: !!id,
    refetchInterval: 20_000,
  });

/* ---- Auth-scan detail for an asset ---- */
export interface HostFacts {
  hostname?: string;
  kernel_release?: string;
  virtualization?: string;
  cpu_model?: string;
  cpu_count?: number;
  memory_mb?: number;
  uptime_seconds?: number;
  boot_time?: string;
  timezone?: string;
  default_gateway?: string;
  primary_mac?: string;
  mac_addresses?: Record<string, string>;
  ipv4_addresses?: string[];
  logged_in_users?: string[];
  selinux?: string;
  pending_updates?: number;
  listening_ports?: Array<{ port: number; protocol: string; address: string; process: string }>;
}
export interface AuthDetails {
  os_details: {
    distro?: string; version?: string; kernel?: string; arch?: string;
    os_family?: string; pretty_name?: string; scan_date?: string;
    system_info?: HostFacts;
  } | null;
  software: Array<{ name: string; version: string; cpe: string; scan_date?: string }>;
  software_count: number;
  cves: Array<{
    cve_id: string; severity: string; cvss_score: number | null;
    description: string; affected_cpe: string; has_exploit: boolean;
    exploit_url?: string; scan_date?: string;
  }>;
  cve_count: number;
}
export const useAuthDetails = (ip: string | null) =>
  useQuery({
    queryKey: ['auth-details', ip],
    queryFn: () => api.get<AuthDetails>(`/api/v1/assets/${ip}/auth-details`),
    enabled: !!ip,
  });

export function useAgentActions() {
  const qc = useQueryClient();
  const inv = () => {
    qc.invalidateQueries({ queryKey: ['agent-telemetry'] });
    qc.invalidateQueries({ queryKey: ['agent'] });
  };
  return {
    remove: useMutation({ mutationFn: (id: number) => api.del(`/api/v1/agents/${id}`), onSuccess: inv }),
    regenKey: useMutation({
      mutationFn: (id: number) => api.post<{ agent_key: string }>(`/api/v1/agents/${id}/generate-key`),
    }),
  };
}

/* ---- Settings / NVD ---- */
export function useSettings() {
  const qc = useQueryClient();
  return {
    all: useQuery({
      queryKey: ['settings'],
      queryFn: () => api.get<{ settings: Record<string, string> }>('/api/v1/settings'),
    }),
    nvdStatus: useQuery({
      queryKey: ['nvd-status'],
      queryFn: () => api.get<any>('/api/v1/nvd-status'),
      refetchInterval: 30_000,
    }),
    nvdKey: useQuery({
      queryKey: ['nvd-key'],
      queryFn: () => api.get<{ has_key: boolean; masked: string }>('/api/v1/settings/nvd-key'),
    }),
    setNvdKey: useMutation({
      mutationFn: (key: string) => api.post('/api/v1/settings/nvd-key', { key }),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['nvd-key'] }),
    }),
  };
}

/* ---- Webhooks ---- */
export function useWebhooks() {
  const qc = useQueryClient();
  const inv = () => qc.invalidateQueries({ queryKey: ['webhooks'] });
  return {
    list: useQuery({
      queryKey: ['webhooks'],
      queryFn: () => api.get<{ webhooks: any[]; available_events: string[] }>('/api/v1/webhooks'),
    }),
    create: useMutation({
      mutationFn: (b: any) => api.post<{ secret: string }>('/api/v1/webhooks', b),
      onSuccess: inv,
    }),
    remove: useMutation({ mutationFn: (id: number) => api.del(`/api/v1/webhooks/${id}`), onSuccess: inv }),
    test: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/webhooks/${id}/test`) }),
  };
}
