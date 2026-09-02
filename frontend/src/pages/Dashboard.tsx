import { Suspense, lazy } from 'react';
import { PageHeading, Panel, Spinner, Stat } from '@/components/ui/primitives';
import {
  useCvss,
  useHeatmap,
  useScanQueue,
  useSummary,
  useTopVulns,
  useTopology,
  useTrends,
} from '@/hooks/useDashboard';
import { SeverityDonut } from '@/components/charts/SeverityDonut';
import { CvssHistogram } from '@/components/charts/CvssHistogram';
import { TrendChart } from '@/components/charts/TrendChart';
import { RiskHeatmap } from '@/components/charts/RiskHeatmap';
import { TopVulnList } from '@/components/charts/TopVulnList';
import { ScanQueuePanel } from '@/components/charts/ScanQueuePanel';

const TopologyGraph = lazy(() =>
  import('@/components/charts/TopologyGraph').then((m) => ({ default: m.TopologyGraph })),
);

interface QueryLike {
  isLoading: boolean;
  isError: boolean;
}

export default function Dashboard() {
  const summary = useSummary();
  const cvss = useCvss();
  const heatmap = useHeatmap();
  const trends = useTrends(30);
  const top = useTopVulns(10);
  const queue = useScanQueue();
  const topology = useTopology();

  const s = summary.data;
  const sev = s?.vulnerabilities.by_severity ?? {};

  return (
    <div>
      <PageHeading
        eyebrow="Live posture"
        title="Environment overview"
        state={
          <>
            <i className="inline-block h-2 w-2 rounded-full bg-lime" /> Continuous
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        <Stat label="Assets" value={s?.assets ?? '—'} />
        <Stat label="Critical" value={sev.critical ?? '—'} tone="critical" />
        <Stat label="High" value={sev.high ?? '—'} tone="high" />
        <Stat label="Medium" value={sev.medium ?? '—'} tone="medium" />
        <Stat label="Exploitable" value={s?.vulnerabilities.exploitable ?? '—'} tone="critical" />
        <Stat
          label="Agents"
          value={s ? `${s.agents.active}/${s.agents.total}` : '—'}
          hint={s ? `${s.agents.stale} stale` : undefined}
        />
        <Stat label="Open ports" value={s?.open_ports ?? '—'} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Severity mix">
          <Guard q={summary}>{s && <SeverityDonut data={sev} />}</Guard>
        </Panel>
        <Panel title="CVSS distribution">
          <Guard q={cvss}>{cvss.data && <CvssHistogram data={cvss.data} />}</Guard>
        </Panel>
        <Panel title="Scan queue" meta={queue.data ? `${queue.data.active} active` : ''}>
          <Guard q={queue}>{queue.data && <ScanQueuePanel data={queue.data} />}</Guard>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="30-day activity">
          <Guard q={trends}>{trends.data && <TrendChart data={trends.data} />}</Guard>
        </Panel>
        <Panel title="Top findings" meta="exploit · cvss · blast radius">
          <Guard q={top}>{top.data && <TopVulnList vulns={top.data.vulnerabilities} />}</Guard>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Risk heatmap" meta="device type × severity">
          <Guard q={heatmap}>{heatmap.data && <RiskHeatmap data={heatmap.data} />}</Guard>
        </Panel>
        <Panel title="Network topology" bodyClassName="p-2">
          <Guard q={topology}>
            {topology.data && (
              <Suspense fallback={<CenterSpinner />}>
                <TopologyGraph data={topology.data} />
              </Suspense>
            )}
          </Guard>
        </Panel>
      </div>
    </div>
  );
}

function Guard({ q, children }: { q: QueryLike; children: React.ReactNode }) {
  if (q.isLoading) return <CenterSpinner />;
  if (q.isError) return <div className="py-8 text-center text-2xs text-danger">Failed to load</div>;
  return <>{children}</>;
}

function CenterSpinner() {
  return (
    <div className="flex h-40 items-center justify-center">
      <Spinner />
    </div>
  );
}
