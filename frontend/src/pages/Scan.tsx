import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { clsx } from 'clsx';
import { PageHeading, Panel, Badge } from '@/components/ui/primitives';
import { useScanRunner, type ScanKind } from '@/hooks/useScanRunner';
import { useScanProfiles, useCredentials } from '@/hooks/useResources';
import { toast } from '@/stores/toast';
import { useUi } from '@/stores/ui';

const MODES: { kind: ScanKind; label: string; hint: string }[] = [
  { kind: 'port', label: 'Port', hint: 'nmap service/version discovery' },
  { kind: 'fingerprint', label: 'Fingerprint', hint: 're-run endpoint identification on known ports' },
  { kind: 'vuln', label: 'Vulnerability', hint: 'Nuclei template scan' },
  { kind: 'auth', label: 'Auth', hint: 'SSH in, inventory packages, version-match CVEs against local NVD' },
];

export default function Scan() {
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<ScanKind>('port');
  const [profile, setProfile] = useState('');
  const [credIds, setCredIds] = useState<string[]>([]);
  const [useAll, setUseAll] = useState(false);
  const runner = useScanRunner();
  const { data: profilesData } = useScanProfiles();
  const { list: creds } = useCredentials();
  const setLogOpen = useUi((s) => s.setLogOpen);

  const profiles = profilesData?.profiles ?? [];
  const activeProfile = useMemo(() => profiles.find((p) => p.id === profile), [profiles, profile]);
  const credList = creds.data?.credentials ?? [];

  const launch = () => {
    const t = target.trim();
    if (!t) {
      toast.error('Enter a target (IP, CIDR, or hostname)');
      return;
    }
    if (mode === 'auth') {
      if (!useAll && credIds.length === 0) {
        toast.error('Select at least one credential, or "use all"');
        return;
      }
      setLogOpen(true);
      runner.start('auth', t, { credentialIds: credIds, useAllCreds: useAll });
      return;
    }
    setLogOpen(true);
    // A vuln profile flagged auth_required routes through auth.
    if (mode === 'vuln' && activeProfile?.auth_required) {
      if (!useAll && credIds.length === 0) {
        toast.error('This profile needs credentials');
        return;
      }
      runner.start('auth', t, { credentialIds: credIds, useAllCreds: useAll });
      return;
    }
    runner.start(mode, t, mode === 'vuln' && profile ? { profile } : {});
  };

  const showCreds = mode === 'auth' || (mode === 'vuln' && activeProfile?.auth_required);

  return (
    <div>
      <PageHeading eyebrow="Target acquisition" title="New trace" state="Manual" />

      <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
        <Panel title="Scan">
          <label className="eyebrow mb-1 block">Target</label>
          <input
            className="input mb-4"
            placeholder="192.168.1.1, 10.0.0.0/24, example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !runner.running && launch()}
          />

          <label className="eyebrow mb-1 block">Method</label>
          <div className="mb-1 grid grid-cols-2 gap-1.5 sm:grid-cols-4">
            {MODES.map((m) => (
              <button
                key={m.kind}
                onClick={() => setMode(m.kind)}
                className={clsx(
                  'rounded border px-2 py-2 font-mono text-2xs uppercase tracking-wider transition-colors',
                  mode === m.kind
                    ? 'border-blue bg-blue/10 text-blue'
                    : 'border-line text-text-soft hover:border-blue/50',
                )}
              >
                {m.label}
              </button>
            ))}
          </div>
          <p className="mb-4 text-2xs text-faint">{MODES.find((m) => m.kind === mode)?.hint}</p>

          {mode === 'vuln' && (
            <div className="mb-4">
              <label className="eyebrow mb-1 block">Scan profile</label>
              <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
                <option value="">Custom</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {(p.icon || '▸') + ' ' + p.name}
                  </option>
                ))}
              </select>
              {activeProfile?.description && (
                <p className="mt-1 text-2xs text-muted">{activeProfile.description}</p>
              )}
            </div>
          )}

          {showCreds && (
            <div className="mb-4 rounded border border-line-soft bg-hover p-3">
              <label className="eyebrow mb-1 block">SSH credentials</label>
              {credList.length === 0 ? (
                <p className="text-2xs text-muted">
                  No credentials configured.{' '}
                  <Link className="text-blue hover:underline" to="/settings">
                    Add one in Control →
                  </Link>
                </p>
              ) : (
                <>
                  <select
                    multiple
                    className="input mb-2 h-24"
                    value={credIds}
                    onChange={(e) =>
                      setCredIds(Array.from(e.target.selectedOptions).map((o) => o.value))
                    }
                  >
                    {credList.map((c) => (
                      <option key={c.id} value={String(c.id)}>
                        {c.name} ({c.cred_type} / {c.username})
                      </option>
                    ))}
                  </select>
                  <label className="flex items-center gap-1.5 text-2xs text-text-soft">
                    <input
                      type="checkbox"
                      checked={useAll}
                      onChange={(e) => setUseAll(e.target.checked)}
                    />
                    try all {credList.length} credentials
                  </label>
                </>
              )}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <button className="btn-primary" disabled={runner.running} onClick={launch}>
              {runner.running ? 'Scanning…' : `Run ${MODES.find((m) => m.kind === mode)?.label} scan`}
            </button>
            {runner.running && (
              <button className="btn" onClick={runner.stop}>
                Stop
              </button>
            )}
          </div>

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
    results?: Array<{
      ip: string;
      success: boolean;
      scan_data?: unknown[][];
      error?: string;
      vuln_count?: number;
      credential?: string;
      packages?: number;
      cves?: number;
    }>;
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {r.target && <Badge>{r.target}</Badge>}
        {r.total != null && <Badge>{r.total} host{r.total === 1 ? '' : 's'}</Badge>}
        {r.successful_count != null && <Badge>{r.successful_count} ok</Badge>}
        {r.failed_count ? (
          <Badge className="border-danger/40 text-danger">{r.failed_count} failed</Badge>
        ) : null}
        {r.total_vulns != null && (
          <Badge className="border-danger/40 text-danger">{r.total_vulns} findings</Badge>
        )}
      </div>
      {r.results?.map((res, i) => (
        <div key={`${res.ip}-${i}`} className="rounded border border-line-soft p-2">
          <div className="data mb-1 text-text">
            {res.ip}
            {res.credential && <span className="ml-2 text-2xs text-muted">via {res.credential}</span>}
          </div>
          {res.error && <div className="text-2xs text-danger">{res.error}</div>}
          {res.packages != null && (
            <div className="text-2xs text-muted">
              {res.packages} packages · {res.cves} CVE match{res.cves === 1 ? '' : 'es'}
            </div>
          )}
          {res.vuln_count != null && (
            <div className="text-2xs text-muted">{res.vuln_count} finding(s)</div>
          )}
          {Array.isArray(res.scan_data) && res.scan_data.length > 0 && (
            <div className="mt-1 space-y-0.5 font-mono text-2xs text-text-soft">
              {res.scan_data.slice(0, 20).map((row, j) => (
                <div key={j}>
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
