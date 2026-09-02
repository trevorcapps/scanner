import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, qs } from '@/lib/api';
import type { AssetSummary, UnifiedVuln } from '@/types';
import { SeverityPill } from '@/components/ui/primitives';

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [vulns, setVulns] = useState<UnifiedVuln[]>([]);
  const nav = useNavigate();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) {
      setQ('');
      setAssets([]);
      setVulns([]);
    }
  }, [open]);

  useEffect(() => {
    if (!open || q.trim().length < 2) {
      setAssets([]);
      setVulns([]);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const [a, v] = await Promise.all([
          api.get<{ assets: AssetSummary[] }>(`/api/v1/assets${qs({ q, per_page: 6, page: 1 })}`),
          api.get<{ vulnerabilities: UnifiedVuln[] }>(
            `/api/v1/vulnerabilities${qs({ search: q, per_page: 6, page: 1 })}`,
          ),
        ]);
        setAssets(a.assets.slice(0, 6));
        setVulns(v.vulnerabilities.slice(0, 6));
      } catch {
        /* ignore */
      }
    }, 180);
    return () => clearTimeout(t);
  }, [q, open]);

  const go = useMemo(
    () => (path: string) => {
      onClose();
      nav(path);
    },
    [nav, onClose],
  );

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center pt-24" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div
        className="panel relative w-full max-w-lg shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          autoFocus
          className="w-full border-b border-line-soft bg-transparent px-4 py-3 font-mono text-sm outline-none placeholder:text-faint"
          placeholder="Search IPs, hostnames, CVEs…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <div className="max-h-80 overflow-y-auto p-2">
          {assets.length === 0 && vulns.length === 0 && (
            <div className="px-3 py-6 text-center text-2xs text-faint">
              {q.length < 2 ? 'Type to search' : 'No matches'}
            </div>
          )}
          {assets.length > 0 && <div className="eyebrow px-3 py-1">Assets</div>}
          {assets.map((a) => (
            <button
              key={a.ip}
              className="flex w-full items-center gap-2 rounded px-3 py-1.5 text-left text-xs hover:bg-hover"
              onClick={() => go(`/assets?q=${encodeURIComponent(a.ip)}`)}
            >
              <span className="data text-text">{a.ip}</span>
              <span className="text-muted">{a.hostname}</span>
              {a.vuln_counts?.total > 0 && (
                <span className="ml-auto font-mono text-2xs text-danger">
                  {a.vuln_counts.total} vuln
                </span>
              )}
            </button>
          ))}
          {vulns.length > 0 && <div className="eyebrow px-3 py-1 pt-2">Findings</div>}
          {vulns.map((v) => (
            <button
              key={v.cve_id}
              className="flex w-full items-center gap-2 rounded px-3 py-1.5 text-left text-xs hover:bg-hover"
              onClick={() => go(`/vulnerabilities?q=${encodeURIComponent(v.cve_id)}`)}
            >
              <SeverityPill severity={v.severity} />
              <span className="data text-text">{v.cve_id}</span>
              <span className="truncate text-muted">{v.vuln_name}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
