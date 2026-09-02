export interface User {
  id: number;
  username: string;
  display_name?: string;
  role: 'admin' | 'analyst' | 'readonly';
  email?: string | null;
}

export interface Pagination {
  page: number;
  per_page: number;
  total: number;
  pages: number;
}

export interface VulnCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface AssetSummary {
  ip: string;
  hostname: string | null;
  reverse_dns: string | null;
  device_type: string | null;
  device_icon: string | null;
  mac_address: string | null;
  mac_vendor: string | null;
  os_name: string | null;
  last_scan: string | null;
  port_count: number;
  vuln_counts: VulnCounts;
  technologies: Array<{ name: string; version?: string; category?: string; confidence: number }>;
  ports: Array<{
    protocol: string;
    port: number;
    state: string;
    service: string;
    product: string;
    version: string;
    fingerprint?: Record<string, unknown>;
  }>;
}

export interface AssetDetail extends AssetSummary {
  first_seen: string | null;
  scan_count: number;
  os_family: string | null;
  aliases: string[];
  vulnerabilities: unknown[];
  fingerprints: unknown[];
  fingerprints_by_port: Record<string, unknown>;
  auth_os: unknown;
  installed_software: unknown[];
  cve_matches: unknown[];
  agent_data: {
    packages: unknown[];
    package_count: number;
    system_info: Record<string, unknown>;
    os_info: Record<string, unknown>;
    updated_at: string;
  } | null;
}

export interface UnifiedVuln {
  cve_id: string;
  vuln_name: string;
  severity: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_id: string | null;
  has_exploit: boolean;
  exploit_ids: string;
  exploit_url: string;
  affected_cpe: string;
  references: Array<{ url: string; source?: string }>;
  affected_assets: Array<{ ip: string; port: number; protocol: string }>;
  detection_sources: string[];
  template_id: string;
  published_date: string | null;
}

export interface DashboardSummary {
  assets: number;
  open_ports: number;
  agents: { total: number; active: number; stale: number; offline: number };
  sites: number;
  schedules_enabled: number;
  vulnerabilities: {
    by_severity: Record<string, number>;
    total: number;
    exploitable: number;
    affected_hosts: number;
  };
  scan_jobs: Record<string, number>;
}

export interface CvssDistribution {
  buckets: Array<{ range: string; min: number; count: number }>;
  unscored: number;
  total: number;
}

export interface TopVuln {
  cve_id: string;
  vuln_name: string;
  severity: string;
  cvss_score: number | null;
  has_exploit: boolean;
  affected_assets: number;
  detection_sources: string[];
}

export interface RiskHeatmap {
  rows: Array<{ device_type: string; critical: number; high: number; medium: number; low: number; total: number }>;
  severities: string[];
  assets: Array<{
    ip: string;
    hostname: string | null;
    device_type: string;
    risk_score: number;
    vuln_counts: VulnCounts;
  }>;
}

export interface Trends {
  days: number;
  series: Array<{ date: string; scans: number; hosts_scanned: number; vulns_found: number; new_vulns: number }>;
}

export interface TopologyNode {
  id: string;
  type: 'root' | 'subnet' | 'asset';
  label: string;
  ip?: string;
  hostname?: string | null;
  device_type?: string;
  port_count?: number;
  worst_severity?: string | null;
  vuln_total?: number;
}

export interface Topology {
  nodes: TopologyNode[];
  links: Array<{ source: string; target: string }>;
  stats: { assets: number; subnets: number };
}

export interface ScanJob {
  id: string;
  job_type: string;
  status: string;
  target: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  result: Record<string, unknown> | null;
  error_message: string | null;
}

export interface ScanQueue {
  counts: Record<string, number>;
  active: number;
  recent: ScanJob[];
}
