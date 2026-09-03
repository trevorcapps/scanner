import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { SlideOver } from '@/components/ui/SlideOver';
import { Modal, Field, FormActions } from '@/components/ui/Modal';
import { Badge, SeverityPill, Spinner } from '@/components/ui/primitives';
import { useAsset, useAssetActions } from '@/hooks/useAssets';
import { useAuth } from '@/hooks/useAuth';
import { useAuthDetails, useCredentials } from '@/hooks/useResources';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

export function AssetDetail({ ip, onClose }: { ip: string | null; onClose: () => void }) {
  const { data, isLoading } = useAsset(ip);
  const actions = useAssetActions(ip ?? '');
  const { user } = useAuth();
  const asset = data?.asset;
  const [authOpen, setAuthOpen] = useState(false);

  const runScan = (scan_type: string, options?: Record<string, unknown>) =>
    actions.scan.mutate(
      options ? { scan_type, options } : scan_type,
      {
        onSuccess: () => toast.success(`${scan_type} scan queued for ${ip}`),
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Scan failed'),
      },
    );

  return (
    <SlideOver
      open={!!ip}
      onClose={onClose}
      title={asset?.hostname ? `${asset.hostname}` : (ip ?? '')}
      subtitle={
        asset ? `${asset.ip} · ${asset.device_type ?? 'unclassified'} · ${asset.os_name ?? 'OS unknown'}` : ip
      }
    >
      {isLoading && (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      )}

      {asset && (
        <div className="space-y-6">
          <div className="flex flex-wrap gap-2">
            <button className="btn-primary" onClick={() => runScan('port')} disabled={actions.scan.isPending}>
              Port scan
            </button>
            <button className="btn" onClick={() => runScan('vuln')} disabled={actions.scan.isPending}>
              Vuln scan
            </button>
            <button className="btn" onClick={() => setAuthOpen(true)} disabled={actions.scan.isPending}>
              Auth scan
            </button>
            <button className="btn" onClick={() => runScan('full')} disabled={actions.scan.isPending}>
              Full
            </button>
            <button
              className="btn"
              onClick={() =>
                actions.reclassify.mutate(undefined, { onSuccess: () => toast.info('Re-classified') })
              }
            >
              Reclassify
            </button>
            {user?.role === 'admin' && (
              <button
                className="btn-danger ml-auto"
                onClick={() => {
                  if (confirm(`Delete asset ${asset.ip} and all its scan data?`)) {
                    actions.remove.mutate(undefined, {
                      onSuccess: () => {
                        toast.success('Asset deleted');
                        onClose();
                      },
                    });
                  }
                }}
              >
                Delete
              </button>
            )}
          </div>

          <Section title="Identity">
            <KV k="IP" v={asset.ip} />
            <KV k="Hostname" v={asset.hostname} />
            <KV k="Reverse DNS" v={asset.reverse_dns} />
            <KV
              k="MAC"
              v={asset.mac_address ? `${asset.mac_address} ${asset.mac_vendor ? `(${asset.mac_vendor})` : ''}` : null}
            />
            <KV k="OS" v={asset.os_name} />
            <KV k="First seen" v={formatDate(asset.first_seen)} />
            <KV k="Last scan" v={formatDate(asset.last_scan)} />
            <KV k="Scans" v={String(asset.scan_count)} />
          </Section>

          <Section title={`Open ports (${asset.ports.filter((p) => p.state === 'open').length})`}>
            <div className="space-y-1">
              {asset.ports
                .filter((p) => p.state === 'open')
                .map((p) => (
                  <div key={`${p.protocol}-${p.port}`} className="flex items-center gap-2 text-xs">
                    <span className="data w-16 text-text">
                      {p.port}/{p.protocol}
                    </span>
                    <span className="text-text-soft">{p.service}</span>
                    <span className="text-muted">{[p.product, p.version].filter(Boolean).join(' ')}</span>
                  </div>
                ))}
              {asset.ports.filter((p) => p.state === 'open').length === 0 && (
                <span className="text-2xs text-faint">No open ports recorded</span>
              )}
            </div>
          </Section>

          {asset.technologies?.length > 0 && (
            <Section title="Technologies">
              <div className="flex flex-wrap gap-1.5">
                {asset.technologies.map((t, i) => (
                  <Badge key={i}>
                    {t.name}
                    {t.version ? ` ${t.version}` : ''}
                  </Badge>
                ))}
              </div>
            </Section>
          )}

          <AuthScanSection ip={asset.ip} />

          {Array.isArray(asset.vulnerabilities) && asset.vulnerabilities.length > 0 && (
            <Section title={`Vulnerabilities (${asset.vulnerabilities.length})`}>
              <div className="space-y-1.5">
                {(asset.vulnerabilities as any[]).map((v, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <SeverityPill severity={v.severity} score={v.cvss_score} />
                    <span className="data text-text">{v.vuln_id}</span>
                    <span className="truncate text-muted">{v.vuln_name}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {asset.agent_data && (
            <Section title="Agent telemetry">
              <KV k="Packages" v={String(asset.agent_data.package_count)} />
              <KV k="Reported" v={formatDate(asset.agent_data.updated_at)} />
            </Section>
          )}
        </div>
      )}

      <AuthScanModal ip={ip} open={authOpen} onClose={() => setAuthOpen(false)} onLaunch={runScan} />
    </SlideOver>
  );
}

function AuthScanModal({
  ip,
  open,
  onClose,
  onLaunch,
}: {
  ip: string | null;
  open: boolean;
  onClose: () => void;
  onLaunch: (type: string, options?: Record<string, unknown>) => void;
}) {
  const { list } = useCredentials();
  const [sel, setSel] = useState<string[]>([]);
  const creds = list.data?.credentials ?? [];

  return (
    <Modal open={open} onClose={onClose} title={`Auth scan · ${ip ?? ''}`}>
      <p className="mb-3 text-2xs text-muted">
        SSH in, inventory installed packages, and version-match CVEs against the local NVD database.
        No changes are made to the target.
      </p>
      {creds.length === 0 ? (
        <p className="text-2xs text-danger">No SSH credentials configured. Add one under Control.</p>
      ) : (
        <Field label="Credentials to try">
          <select
            multiple
            className="input h-28"
            value={sel}
            onChange={(e) => setSel(Array.from(e.target.selectedOptions).map((o) => o.value))}
          >
            {creds.map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name} ({c.cred_type} / {c.username})
              </option>
            ))}
          </select>
        </Field>
      )}
      <FormActions>
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn-primary"
          disabled={creds.length === 0}
          onClick={() => {
            const ids = sel.length ? sel.map(Number) : creds.map((c) => c.id);
            onLaunch('auth', { credential_ids: ids });
            onClose();
          }}
        >
          Run auth scan
        </button>
      </FormActions>
    </Modal>
  );
}

function AuthScanSection({ ip }: { ip: string }) {
  const { data, isLoading } = useAuthDetails(ip);
  const nav = useNavigate();
  const [filter, setFilter] = useState('');

  if (isLoading) {
    return (
      <Section title="Authenticated scan">
        <div className="py-3">
          <Spinner />
        </div>
      </Section>
    );
  }
  if (!data || (data.software_count === 0 && data.cve_count === 0 && !data.os_details)) {
    return (
      <Section title="Authenticated scan">
        <p className="text-2xs text-faint">No authenticated scan data. Run an Auth scan above.</p>
      </Section>
    );
  }

  const os = data.os_details;
  const software = filter
    ? data.software.filter(
        (s) =>
          s.name.toLowerCase().includes(filter.toLowerCase()) ||
          s.cpe.toLowerCase().includes(filter.toLowerCase()),
      )
    : data.software;

  return (
    <Section title="Authenticated scan">
      {os && (
        <div className="mb-3 grid grid-cols-2 gap-x-4">
          <KV k="Distro" v={os.pretty_name || os.distro} />
          <KV k="Version" v={os.version} />
          <KV k="Arch" v={os.arch} />
          <KV k="Scanned" v={formatDate(os.scan_date)} />
          {os.kernel && <KV k="Kernel" v={os.kernel} />}
        </div>
      )}

      {data.cve_count > 0 && (
        <div className="mb-4">
          <div className="eyebrow mb-1">CVE matches ({data.cve_count})</div>
          <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
            {data.cves.map((c) => (
              <button
                key={c.cve_id}
                className="flex w-full items-center gap-2 rounded px-1 py-1 text-left text-xs hover:bg-hover"
                onClick={() => nav(`/vulnerabilities?q=${encodeURIComponent(c.cve_id)}`)}
              >
                <SeverityPill severity={c.severity} score={c.cvss_score} />
                <span className="data text-text">{c.cve_id}</span>
                {c.has_exploit && <Badge className="border-danger/40 text-danger">exploit</Badge>}
                <span className="truncate text-2xs text-muted">{c.description}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="eyebrow">Installed software ({data.software_count})</span>
          <input
            className="input h-6 w-40 py-0 text-2xs"
            placeholder="filter…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <div className="max-h-64 overflow-y-auto rounded border border-line-soft">
          <table className="w-full text-2xs">
            <tbody>
              {software.slice(0, 500).map((s) => (
                <tr key={s.name} className="border-b border-line-soft last:border-0">
                  <td className="px-2 py-1 font-mono text-text-soft">{s.name}</td>
                  <td className="px-2 py-1 font-mono text-muted">{s.version}</td>
                  <td className="px-2 py-1 font-mono text-faint">{s.cpe}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {software.length > 500 && (
            <div className="px-2 py-1 text-2xs text-faint">showing 500 of {software.length}</div>
          )}
        </div>
      </div>
    </Section>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow mb-2 border-b border-line-soft pb-1">{title}</div>
      {children}
    </div>
  );
}

function KV({ k, v }: { k: string; v?: string | null }) {
  return (
    <div className="flex gap-3 py-0.5 text-xs">
      <span className="w-28 shrink-0 font-mono text-2xs uppercase tracking-wide text-muted">{k}</span>
      <span className="break-all text-text-soft">{v || '—'}</span>
    </div>
  );
}
