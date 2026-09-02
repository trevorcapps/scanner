import { useNavigate } from 'react-router-dom';
import { SeverityPill } from '@/components/ui/primitives';
import type { TopVuln } from '@/types';

export function TopVulnList({ vulns }: { vulns: TopVuln[] }) {
  const nav = useNavigate();
  if (vulns.length === 0) {
    return <div className="py-8 text-center text-2xs text-faint">No findings</div>;
  }
  return (
    <ol className="divide-y divide-line-soft">
      {vulns.map((v, i) => (
        <li key={v.cve_id}>
          <button
            className="flex w-full items-center gap-3 px-1 py-2 text-left text-xs hover:bg-hover"
            onClick={() => nav(`/vulnerabilities?q=${encodeURIComponent(v.cve_id)}`)}
          >
            <span className="w-5 shrink-0 text-right font-mono text-2xs text-faint">{i + 1}</span>
            <SeverityPill severity={v.severity} score={v.cvss_score} />
            <span className="data shrink-0 text-text">{v.cve_id}</span>
            <span className="truncate text-muted">{v.vuln_name}</span>
            <span className="ml-auto flex shrink-0 items-center gap-2 font-mono text-2xs">
              {v.has_exploit && <span className="text-danger">EXPLOIT</span>}
              <span className="text-text-soft">{v.affected_assets}⌂</span>
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}
