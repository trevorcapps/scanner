import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

export type ReportKind = 'executive' | 'technical' | 'full';
export type ReportFormat = 'pdf' | 'html';

export interface ReportScope {
  type: 'environment' | 'site' | 'filter';
  id?: number;
  min_severity?: string;
  device_type?: string;
  subnet?: string;
}

export interface Report {
  id: number;
  title: string;
  kind: ReportKind;
  format: ReportFormat;
  scope: ReportScope;
  status: 'ready' | 'failed';
  error?: string | null;
  size_bytes: number;
  summary: {
    assets?: number;
    affected_hosts?: number;
    unique_cves?: number;
    exploitable?: number;
    risk_score?: number;
    open_ports?: number;
    by_severity?: Record<string, number>;
  };
  created_at: string;
  schedule_id?: number | null;
}

export interface ReportSchedule {
  id: number;
  name: string;
  kind: ReportKind;
  format: ReportFormat;
  scope: ReportScope;
  cron_expression: string;
  recipients: string[];
  enabled: boolean;
  last_run?: string | null;
  next_run?: string | null;
  last_status?: string | null;
  last_error?: string | null;
}

export interface RiskPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  exploitable: number;
  risk_score: number;
  unique_cves: number;
}

export function useReports() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ['reports'],
    queryFn: () => api.get<{ reports: Report[] }>('/api/v1/reports'),
  });
  const generate = useMutation({
    mutationFn: (body: { kind: ReportKind; format: ReportFormat; scope: ReportScope }) =>
      api.post<{ report: Report }>('/api/v1/reports', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }),
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/api/v1/reports/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }),
  });
  return { list, generate, remove };
}

export const useRiskTrends = (days = 90) =>
  useQuery({
    queryKey: ['report-trends', days],
    queryFn: () => api.get<{ days: number; series: RiskPoint[] }>(`/api/v1/reports/trends?days=${days}`),
  });

export function useReportSchedules() {
  const qc = useQueryClient();
  const inv = () => qc.invalidateQueries({ queryKey: ['report-schedules'] });
  return {
    list: useQuery({
      queryKey: ['report-schedules'],
      queryFn: () => api.get<{ schedules: ReportSchedule[] }>('/api/v1/report-schedules'),
    }),
    create: useMutation({ mutationFn: (b: unknown) => api.post('/api/v1/report-schedules', b), onSuccess: inv }),
    update: useMutation({
      mutationFn: ({ id, body }: { id: number; body: unknown }) =>
        api.put(`/api/v1/report-schedules/${id}`, body),
      onSuccess: inv,
    }),
    remove: useMutation({ mutationFn: (id: number) => api.del(`/api/v1/report-schedules/${id}`), onSuccess: inv }),
    run: useMutation({ mutationFn: (id: number) => api.post(`/api/v1/report-schedules/${id}/run`), onSuccess: inv }),
  };
}

export interface Branding {
  report_org_name: string;
  report_logo: string;
  report_accent_color: string;
  report_footer: string;
  report_confidentiality: string;
}

export function useBranding() {
  const qc = useQueryClient();
  return {
    get: useQuery({ queryKey: ['report-branding'], queryFn: () => api.get<Branding>('/api/v1/reports/branding') }),
    save: useMutation({
      mutationFn: (b: Partial<Branding>) => api.put('/api/v1/reports/branding', b),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['report-branding'] }),
    }),
  };
}

export interface SmtpConfig {
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_from: string;
  smtp_security: string;
  smtp_password_set: boolean;
}

export function useSmtp() {
  const qc = useQueryClient();
  return {
    get: useQuery({ queryKey: ['smtp'], queryFn: () => api.get<SmtpConfig>('/api/v1/reports/smtp') }),
    save: useMutation({
      mutationFn: (b: Record<string, unknown>) => api.put('/api/v1/reports/smtp', b),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['smtp'] }),
    }),
    test: useMutation({
      mutationFn: (recipient: string) => api.post('/api/v1/reports/test-email', { recipient }),
    }),
  };
}
