import { useMemo, useState } from 'react';
import { PageHeading, Panel, Badge } from '@/components/ui/primitives';
import { useScanRunner } from '@/hooks/useScanRunner';
import { useScanProfiles, useCredentials } from '@/hooks/useResources';
import { toast } from '@/stores/toast';
import { useUi } from '@/stores/ui';

export default function Scan() {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('');
  const [credIds, setCredIds] = useState<string[]>([]);
  const [useAll, setUseAll] = useState(false);
  const runner = useScanRunner();
  const { data: profilesData } = useScanProfiles();
  const { list: creds } = useCredentials();
  const setLogOpen = useUi((s) => s.setLogOpen);

  const profiles = profilesData?.profiles ?? [];
  const activeProfile = useMemo(() => profiles.find((p) => p.id === profile), [profiles, profile]);
  const authNeeded = !!activeProfile?.auth_required;

  const launch = (kind: 'port' | 'fingerprint' | 'vuln') => {
    const t = target.trim();
    if (!t) {
      toast.error('Enter a target (IP, CIDR, or hostname)');
      return;
    }
    setLogOpen(true);
    if (kind === 'vuln' && authNeeded) {
      if (!useAll && credIds.length === 0) {
        toast.error('Select credentials or "use all"');
        return;
      }
      runner.start('auth', t, { credentialIds: credIds, useAllCreds: useAll });
      return;
    }
    runner.start(kind, t, kind === 'vuln' && profile ? { profile } : {});
  };

  return (
    <div>
      <PageHeading eyebrow="Target acquisition" title="New trace" state="Manual" />

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <Panel title="Scan">
          <label className="eyebrow mb-1 block">Target</label>
          <input
            className="input mb-4"
            placeholder="192.168.1.1, 10.0.0.0/24, example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && launch('port')}
          />

          <div className="mb-4 flex flex-wrap gap-2">
            <button className="btn-primary" disabled={runner.running} onClick={() => launch('port')}>
              {runner.running && runner.kind === 'port' ? 'Scanning…' : 'Port scan'}
            </button>
            <button className="btn" disabled={runner.running} onClick={() => launch('fingerprint')}>
              {runner.running && runner.kind === 'fingerprint' ? 'Fingerprinting…' : 'Fingerprint'}
            </button>
            <button className="btn-danger" disabled={runner.running} onClick={() => launch('vuln')}>
              {runner.running && (runner.kind === 'vuln' || runner.kind === 'auth')
                ? 'Scanning…'
                : authNeeded
                  ? 'Auth scan'
                  : 'Vulnerability scan'}
            </button>
            {runner.running && (
              <button className="btn" onClick={runner.stop}>
                Stop
              </button>
            )}
          </div>

          <label className="eyebrow mb-1 block">Scan profile</label>
          <select className="input mb-3" value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="">Custom</option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {(p.icon || '▸') + ' ' + p.name}
              </option>
            ))}
          </select>
          {activeProfile?.description && (
            <p className="mb-3 text-2xs text-muted">{activeProfile.description}</p>
          )}

          {authNeeded && (
            <div className="rounded border border-line-soft bg-hover p-3">
              <label className="eyebrow mb-1 block">Credentials</label>
              <select
                multiple
                className="input mb-2 h-24"
                value={credIds}
                onChange={(e) =>
                  setCredIds(Array.from(e.target.selectedOptions).map((o) => o.value))
                }
              >
                {(creds.data?.credentials ?? []).map((c) => (
                  <option key={c.id} value={String(c.id)}>
                    {c.name} ({c.cred_type} / {c.username})
                  </option>
                ))}
              </select>
              <label className="flex items-center gap-1.5 text-2xs text-text-soft">
                <input type="checkbox" checked={useAll} onChange={(e) => setUseAll(e.target.checked)} />
                use all available credentials
              </label>
            </div>
          )}

          {runner.progress && (
            <div className="mt-4">
              <div className="mb-1 flex justify-between font-mono text-2xs text-text-soft">
                <span>{runner.progress.message}</span>
                <span>
                  {runner.progress.current}/{runner.progress.total}
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded bg-hover">
                <div
                  className="h-full bg-blue transition-all"
                  style={{
                    width: `${Math.min(100, (runner.progress.current / (runner.progress.total || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>
          )}
          {runner.error && <p className="mt-3 text-2xs text-danger">{runner.error}</p>}
        </Panel>

        <Panel title="Last result" bodyClassName="p-4 text-xs">
          <ScanResult result={runner.result} running={runner.running} />
        </Panel>
      </div>
    </div>
  );
}

function ScanResult({ result, running }: { result: unknown; running: boolean }) {
  if (running) return <p className="text-muted">Scan running — see the activity log.</p>;
  if (!result) return <p className="text-faint">No scan run yet this session.</p>;

  const r = result as {
    target?: string;
    total?: number;
    successful_count?: number;
    failed_count?: number;
    total_vulns?: number;
    results?: Array<{ ip: string; success: boolean; scan_data?: unknown[][]; error?: string; vuln_count?: number }>;
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {r.target && <Badge>{r.target}</Badge>}
        {r.total != null && <Badge>{r.total} host{r.total === 1 ? '' : 's'}</Badge>}
        {r.successful_count != null && <Badge>{r.successful_count} ok</Badge>}
        {r.failed_count ? <Badge className="border-danger/40 text-danger">{r.failed_count} failed</Badge> : null}
        {r.total_vulns != null && (
          <Badge className="border-danger/40 text-danger">{r.total_vulns} findings</Badge>
        )}
      </div>
      {r.results?.map((res) => (
        <div key={res.ip} className="rounded border border-line-soft p-2">
          <div className="data mb-1 text-text">{res.ip}</div>
          {res.error && <div className="text-2xs text-danger">{res.error}</div>}
          {res.vuln_count != null && (
            <div className="text-2xs text-muted">{res.vuln_count} finding(s)</div>
          )}
          {Array.isArray(res.scan_data) && res.scan_data.length > 0 && (
            <div className="mt-1 space-y-0.5 font-mono text-2xs text-text-soft">
              {res.scan_data.slice(0, 20).map((row, i) => (
                <div key={i}>
                  {String(row[1])}/{String(row[0])} {String(row[2])} · {String(row[3])}{' '}
                  {[row[4], row[5]].filter(Boolean).join(' ')}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
