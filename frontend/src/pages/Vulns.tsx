import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { PageHeading, Panel, SeverityPill, Badge } from '@/components/ui/primitives';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { useVulnList } from '@/hooks/useVulns';
import type { UnifiedVuln } from '@/types';
import { VulnDetail } from './VulnDetail';

export default function Vulns() {
  const [sp, setSp] = useSearchParams();
  const [detail, setDetail] = useState<UnifiedVuln | null>(null);

  const search = sp.get('q') ?? '';
  const source = sp.get('source') ?? '';
  const severity = sp.get('severity') ?? '';
  const has_exploit = sp.get('exploit') === '1';
  const sort = sp.get('sort') ?? 'cvss';
  const order = (sp.get('order') as 'asc' | 'desc') ?? 'desc';
  const page = Number(sp.get('page') ?? 1);

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== 'page') next.delete('page');
    setSp(next, { replace: true });
  };

  const { data, isLoading, isFetching } = useVulnList({
    search, source, severity, has_exploit: has_exploit || undefined, sort, order, page, per_page: 25,
  });

  const toggleSort = (key: string) => {
    if (sort === key) setParam('order', order === 'asc' ? 'desc' : 'asc');
    else {
      const next = new URLSearchParams(sp);
      next.set('sort', key);
      next.set('order', 'desc');
      next.delete('page');
      setSp(next, { replace: true });
    }
  };

  const columns: Column<UnifiedVuln>[] = [
    {
      key: 'severity',
      header: 'Severity',
      sortable: true,
      className: 'w-28',
      render: (v) => <SeverityPill severity={v.severity} />,
    },
    { key: 'cve_id', header: 'ID', render: (v) => <span className="data text-text">{v.cve_id}</span> },
    { key: 'name', header: 'Name', sortable: true, render: (v) => <span className="truncate text-muted">{v.vuln_name}</span> },
    {
      key: 'cvss',
      header: 'CVSS',
      sortable: true,
      className: 'w-16 text-center',
      render: (v) => <span className="data">{v.cvss_score?.toFixed(1) ?? '—'}</span>,
    },
    {
      key: 'assets',
      header: 'Hosts',
      sortable: true,
      className: 'w-16 text-center',
      render: (v) => <span className="data">{v.affected_assets.length}</span>,
    },
    {
      key: 'sources',
      header: 'Sources',
      render: (v) => (
        <div className="flex flex-wrap gap-1">
          {v.has_exploit && <Badge className="border-danger/40 text-danger">exploit</Badge>}
          {v.detection_sources.map((s) => (
            <Badge key={s}>{s}</Badge>
          ))}
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeading
        eyebrow="Correlated exposure"
        title="Findings"
        state={data ? `${data.filtered_total} findings` : ''}
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line-soft p-3">
          <input
            className="input max-w-xs flex-1"
            placeholder="Search CVE, description, CPE…"
            defaultValue={search}
            onChange={(e) => setParam('q', e.target.value.trim())}
          />
          <select className="input w-auto" value={severity} onChange={(e) => setParam('severity', e.target.value)}>
            <option value="">any severity</option>
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select className="input w-auto" value={source} onChange={(e) => setParam('source', e.target.value)}>
            <option value="">any source</option>
            {['nuclei', 'nvd-local', 'auth-scan', 'agent', 'exploit-db'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 font-mono text-2xs text-text-soft">
            <input
              type="checkbox"
              checked={has_exploit}
              onChange={(e) => setParam('exploit', e.target.checked ? '1' : '')}
            />
            exploit only
          </label>
          {isFetching && <span className="font-mono text-2xs text-faint">…</span>}
        </div>

        <DataTable
          columns={columns}
          rows={data?.vulnerabilities ?? []}
          rowKey={(v) => v.cve_id}
          onRowClick={setDetail}
          sort={sort}
          order={order}
          onSort={toggleSort}
          pagination={data?.pagination}
          onPage={(p) => setParam('page', String(p))}
          loading={isLoading}
          empty="No findings match these filters."
        />
      </Panel>

      <VulnDetail vuln={detail} onClose={() => setDetail(null)} />
    </div>
  );
}
