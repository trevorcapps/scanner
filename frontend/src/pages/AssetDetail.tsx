import { SlideOver } from '@/components/ui/SlideOver';
import { Badge, SeverityPill, Spinner } from '@/components/ui/primitives';
import { useAsset, useAssetActions } from '@/hooks/useAssets';
import { useAuth } from '@/hooks/useAuth';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

export function AssetDetail({ ip, onClose }: { ip: string | null; onClose: () => void }) {
  const { data, isLoading } = useAsset(ip);
  const actions = useAssetActions(ip ?? '');
  const { user } = useAuth();
  const asset = data?.asset;

  const runScan = (type: string) =>
    actions.scan.mutate(type, {
      onSuccess: () => toast.success(`${type} scan queued for ${ip}`),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Scan failed'),
    });

  return (
    <SlideOver
      open={!!ip}
      onClose={onClose}
      title={asset?.hostname ? `${asset.hostname}` : (ip ?? '')}
      subtitle={asset ? `${asset.ip} · ${asset.device_type ?? 'unclassified'} · ${asset.os_name ?? 'OS unknown'}` : ip}
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
            <KV k="MAC" v={asset.mac_address ? `${asset.mac_address} ${asset.mac_vendor ? `(${asset.mac_vendor})` : ''}` : null} />
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
                    <span className="data w-16 text-text">{p.port}/{p.protocol}</span>
                    <span className="text-text-soft">{p.service}</span>
                    <span className="text-muted">
                      {[p.product, p.version].filter(Boolean).join(' ')}
                    </span>
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
    </SlideOver>
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
      <span className="text-text-soft">{v || '—'}</span>
    </div>
  );
}
