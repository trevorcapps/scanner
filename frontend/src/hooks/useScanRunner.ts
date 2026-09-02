import { useCallback, useEffect, useRef, useState } from 'react';
import { getSocket } from '@/lib/socket';
import { useUi } from '@/stores/ui';
import { useQueryClient } from '@tanstack/react-query';

export type ScanKind = 'port' | 'fingerprint' | 'vuln' | 'auth';

interface Progress {
  message: string;
  current: number;
  total: number;
}

export interface ScanRunState {
  running: boolean;
  kind: ScanKind | null;
  progress: Progress | null;
  result: unknown | null;
  error: string | null;
}

export function useScanRunner() {
  const scanDefaults = useUi((s) => s.scanDefaults);
  const qc = useQueryClient();
  const [state, setState] = useState<ScanRunState>({
    running: false,
    kind: null,
    progress: null,
    result: null,
    error: null,
  });
  const kindRef = useRef<ScanKind | null>(null);

  useEffect(() => {
    const s = getSocket();
    const finish = (result: unknown) => {
      setState((p) => ({ ...p, running: false, result, progress: null }));
      qc.invalidateQueries({ queryKey: ['assets'] });
      qc.invalidateQueries({ queryKey: ['vulns'] });
      qc.invalidateQueries({ queryKey: ['dash'] });
    };
    const onProgress = (d: Progress) => setState((p) => ({ ...p, progress: d }));
    const onError = (d: { error: string }) =>
      setState((p) => ({ ...p, running: false, error: d.error, progress: null }));

    s.on('scan_progress', onProgress);
    s.on('vuln_scan_progress', onProgress);
    s.on('scan_complete', finish);
    s.on('vuln_scan_complete', finish);
    s.on('auth_scan_complete', finish);
    s.on('scan_error', onError);
    s.on('vuln_scan_error', onError);
    return () => {
      s.off('scan_progress', onProgress);
      s.off('vuln_scan_progress', onProgress);
      s.off('scan_complete', finish);
      s.off('vuln_scan_complete', finish);
      s.off('auth_scan_complete', finish);
      s.off('scan_error', onError);
      s.off('vuln_scan_error', onError);
    };
  }, [qc]);

  const start = useCallback(
    (kind: ScanKind, target: string, opts: { profile?: string; credentialIds?: string[]; useAllCreds?: boolean } = {}) => {
      const s = getSocket();
      kindRef.current = kind;
      setState({ running: true, kind, progress: null, result: null, error: null });
      const d = scanDefaults;
      if (kind === 'port') {
        s.emit('start_scan', {
          ip: target, ports: d.ports, scan_speed: d.scanSpeed,
          host_timeout: d.hostTimeout, max_hosts: d.maxHosts, vulscan: d.vulscan,
        });
      } else if (kind === 'fingerprint') {
        s.emit('start_fingerprint_scan', { ip: target });
      } else if (kind === 'vuln') {
        s.emit('start_vuln_scan', {
          ip: target, vuln_timeout: d.vulnTimeout, severity: d.severity,
          rate_limit: d.rateLimit, templates: d.templates, max_hosts: d.maxHosts,
          ...(opts.profile ? { profile: opts.profile } : {}),
        });
      } else if (kind === 'auth') {
        s.emit('start_auth_scan', {
          ip: target,
          credential_ids: opts.credentialIds ?? [],
          use_all_credentials: !!opts.useAllCreds,
        });
      }
    },
    [scanDefaults],
  );

  const stop = useCallback(() => {
    getSocket().emit('stop_scan');
    setState((p) => ({ ...p, running: false, progress: null }));
  }, []);

  return { ...state, start, stop };
}
