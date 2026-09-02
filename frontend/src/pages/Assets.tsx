import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { PageHeading, Panel, SeverityPill, Badge } from '@/components/ui/primitives';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { useAssetList } from '@/hooks/useAssets';
import { formatDate } from '@/lib/format';
import type { AssetSummary } from '@/types';
import { AssetDetail } from './AssetDetail';

const DEVICE_TYPES = [
  '', 'computer', 'server', 'router', 'switch', 'firewall', 'printer', 'iot',
  'mobile', 'nas', 'hypervisor', 'unknown',
];

export default function Assets() {
  const [sp, setSp] = useSearchParams();
  const [detailIp, setDetailIp] = useState<string | null>(null);

  const q = sp.get('q') ?? '';
  const device_type = sp.get('device_type') ?? '';
  const severity = sp.get('severity') ?? '';
  const sort = sp.get('sort') ?? 'last_scan';
  const order = (sp.get('order') as 'asc' | 'desc') ?? 'desc';
  const page = Number(sp.get('page') ?? 1);

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== 'page') next.delete('page');
    setSp(next, { replace: true });
  };

  const { data, isLoading, isFetching } = useAssetList({
    q, device_type, severity, sort, order, page, per_page: 25,
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

  const columns: Column<AssetSummary>[] = [
    {
      key: 'ip',
      header: 'Host',
      sortable: true,
      render: (a) => (
        <div className="flex items-center gap-2">
          {a.device_icon && <span>{a.device_icon}</span>}
          <span className="data text-text">{a.ip}</span>
          {a.hostname && <span className="text-muted">{a.hostname}</span>}
        </div>
      ),
    },
    {
      key: 'device_type',
      header: 'Type',
      render: (a) => (a.device_type ? <Badge>{a.device_type}</Badge> : <span className="text-faint">—</span>),
    },
    { key: 'port_count', header: 'Ports', sortable: true, className: 'w-16 text-center', render: (a) => <span className="data">{a.port_count}</span> },
    {
      key: 'risk',
      header: 'Findings',
      sortable: true,
      render: (a) => {
        const vc = a.vuln_counts;
        if (!vc?.total) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {(['critical', 'high', 'medium', 'low'] as const).map(
              (s) => vc[s] > 0 && <SeverityPill key={s} severity={s} />,
            )}
          </div>
        );
      },
    },
    {
      key: 'last_scan',
      header: 'Last scan',
      sortable: true,
      className: 'w-32',
      render: (a) => <span className="font-mono text-2xs text-muted">{formatDate(a.last_scan)}</span>,
    },
  ];

  return (
    <div>
      <PageHeading
        eyebrow="Discovered inventory"
        title="Assets"
        state={data ? `${data.pagination.total} hosts` : ''}
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line-soft p-3">
          <input
            className="input max-w-xs flex-1"
            placeholder="Search IP or hostname…"
            defaultValue={q}
            onChange={(e) => setParam('q', e.target.value.trim())}
          />
          <select className="input w-auto" value={device_type} onChange={(e) => setParam('device_type', e.target.value)}>
            {DEVICE_TYPES.map((d) => (
              <option key={d} value={d}>
                {d || 'any type'}
              </option>
            ))}
          </select>
          <select className="input w-auto" value={severity} onChange={(e) => setParam('severity', e.target.value)}>
            <option value="">any severity</option>
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <option key={s} value={s}>
                has {s}
              </option>
            ))}
          </select>
          {isFetching && <span className="font-mono text-2xs text-faint">…</span>}
        </div>

        <DataTable
          columns={columns}
          rows={data?.assets ?? []}
          rowKey={(a) => a.ip}
          onRowClick={(a) => setDetailIp(a.ip)}
          sort={sort}
          order={order}
          onSort={toggleSort}
          pagination={data?.pagination}
          onPage={(p) => setParam('page', String(p))}
          loading={isLoading}
          empty="No assets match these filters."
        />
      </Panel>

      <AssetDetail ip={detailIp} onClose={() => setDetailIp(null)} />
    </div>
  );
}
