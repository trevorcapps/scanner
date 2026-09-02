import { useNavigate } from 'react-router-dom';
import { SlideOver } from '@/components/ui/SlideOver';
import { Badge, SeverityPill } from '@/components/ui/primitives';
import { formatDate } from '@/lib/format';
import type { UnifiedVuln } from '@/types';

export function VulnDetail({ vuln, onClose }: { vuln: UnifiedVuln | null; onClose: () => void }) {
  const nav = useNavigate();
  const isCve = vuln?.cve_id?.toUpperCase().startsWith('CVE-');

  return (
    <SlideOver
      open={!!vuln}
      onClose={onClose}
      title={
        vuln && isCve ? (
          <a
            className="text-blue hover:underline"
            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
            target="_blank"
            rel="noreferrer"
          >
            {vuln.cve_id} ↗
          </a>
        ) : (
          (vuln?.cve_id ?? '')
        )
      }
      subtitle={vuln?.vuln_name}
    >
      {vuln && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={vuln.severity} score={vuln.cvss_score} />
            {vuln.cwe_id && <Badge>{vuln.cwe_id}</Badge>}
            {vuln.has_exploit && <Badge className="border-danger/40 text-danger">public exploit</Badge>}
            {vuln.detection_sources.map((s) => (
              <Badge key={s}>{s}</Badge>
            ))}
            {vuln.published_date && (
              <span className="font-mono text-2xs text-faint">published {formatDate(vuln.published_date)}</span>
            )}
          </div>

          {vuln.cvss_vector && (
            <div className="rounded border border-line-soft bg-hover px-3 py-2 font-mono text-2xs text-text-soft">
              {vuln.cvss_vector}
            </div>
          )}

          <div>
            <div className="eyebrow mb-1">Description</div>
            <p className="whitespace-pre-wrap text-xs leading-relaxed text-text-soft">
              {vuln.description || 'No description available.'}
            </p>
          </div>

          <div>
            <div className="eyebrow mb-2 border-b border-line-soft pb-1">
              Affected assets ({vuln.affected_assets.length})
            </div>
            <div className="flex flex-wrap gap-1.5">
              {vuln.affected_assets.map((a, i) => (
                <button
                  key={i}
                  className="rounded border border-line bg-hover px-2 py-1 font-mono text-2xs text-text-soft hover:border-blue hover:text-text"
                  onClick={() => {
                    onClose();
                    nav(`/assets?q=${encodeURIComponent(a.ip)}`);
                  }}
                >
                  {a.ip}
                  {a.port ? `:${a.port}` : ''}
                </button>
              ))}
            </div>
          </div>

          {vuln.affected_cpe && (
            <div>
              <div className="eyebrow mb-1">CPE</div>
              <div className="font-mono text-2xs text-text-soft">{vuln.affected_cpe}</div>
            </div>
          )}

          {(vuln.has_exploit || vuln.exploit_url) && (
            <div>
              <div className="eyebrow mb-1">Exploits</div>
              <div className="flex flex-col gap-1 text-xs">
                {vuln.exploit_ids
                  ?.split(',')
                  .filter(Boolean)
                  .map((id) => (
                    <a
                      key={id}
                      className="text-blue hover:underline"
                      href={`https://www.exploit-db.com/exploits/${id.trim()}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      ExploitDB #{id.trim()} ↗
                    </a>
                  ))}
                {vuln.exploit_url && (
                  <a className="break-all text-blue hover:underline" href={vuln.exploit_url} target="_blank" rel="noreferrer">
                    {vuln.exploit_url} ↗
                  </a>
                )}
              </div>
            </div>
          )}

          {vuln.references?.length > 0 && (
            <div>
              <div className="eyebrow mb-1">References</div>
              <ul className="space-y-0.5 text-xs">
                {vuln.references.map((r, i) => (
                  <li key={i}>
                    <a className="break-all text-blue hover:underline" href={r.url} target="_blank" rel="noreferrer">
                      {r.url}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </SlideOver>
  );
}
