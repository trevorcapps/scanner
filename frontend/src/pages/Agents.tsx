import { useEffect, useState } from 'react';
import { PageHeading, Panel, Stat, StatusDot, Spinner } from '@/components/ui/primitives';
import { useAgent, useAgentActions, useAgentTelemetry } from '@/hooks/useResources';
import { formatDate, relativeTime } from '@/lib/format';
import { toast } from '@/stores/toast';

export default function Agents() {
  const tele = useAgentTelemetry();
  const [selected, setSelected] = useState<number | null>(null);
  const agents: any[] = tele.data?.agents ?? [];

  useEffect(() => {
    if (agents.length && (selected == null || !agents.some((a) => a.id === selected))) {
      setSelected(agents[0].id);
    }
  }, [agents, selected]);

  const t = tele.data;
  const origin = window.location.origin;

  return (
    <div>
      <PageHeading eyebrow="Endpoint telemetry" title="Agents" state="EDR" />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Active" value={t ? `${t.statuses?.active ?? 0}/${t.agents_total ?? 0}` : '—'} />
        <Stat label="Reports 24h" value={t?.reports_24h ?? '—'} />
        <Stat label="Avg CPU" value={t?.average_cpu_percent != null ? `${t.average_cpu_percent}%` : '—'} />
        <Stat label="Avg MEM" value={t?.average_memory_percent != null ? `${t.average_memory_percent}%` : '—'} />
        <Stat
          label="Collection"
          value={t?.average_collection_ms != null ? `${Math.round(t.average_collection_ms)}ms` : '—'}
        />
        <Stat label="Packages" value={t?.packages_observed ?? '—'} />
      </div>

      {tele.isLoading && (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      )}

      {t && agents.length === 0 && (
        <Panel title="Deploy an agent" className="mt-4">
          <p className="mb-3 text-xs text-text-soft">Run on a Linux endpoint with sudo access.</p>
          <CommandBlock cmd={`curl -fsSL ${origin}/agent/install.sh | bash -s -- --server ${origin}`} />
        </Panel>
      )}

      {agents.length > 0 && (
        <div className="mt-4 grid gap-4 lg:grid-cols-[300px_1fr]">
          <Panel title="Catalog" meta={`${agents.length}`} bodyClassName="p-0">
            <ul className="divide-y divide-line-soft">
              {agents.map((a) => (
                <li key={a.id}>
                  <button
                    className={`flex w-full flex-col gap-0.5 px-3 py-2 text-left text-xs ${
                      a.id === selected ? 'bg-hover' : 'hover:bg-hover'
                    }`}
                    onClick={() => setSelected(a.id)}
                  >
                    <span className="flex items-center gap-1.5">
                      <StatusDot status={a.status} />
                      <span className="data text-text">{a.hostname || a.ip || 'unknown'}</span>
                    </span>
                    <span className="text-2xs text-muted">
                      {a.ip || 'no address'} · {a.port_count || 0} ports · CPU{' '}
                      {a.telemetry?.cpu_percent != null ? `${a.telemetry.cpu_percent}%` : '—'}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Panel>

          <AgentInspector id={selected} />
        </div>
      )}

      <Panel title="Deploy / remove" className="mt-4">
        <p className="eyebrow mb-1">Install</p>
        <CommandBlock cmd={`curl -fsSL ${origin}/agent/install.sh | bash -s -- --server ${origin}`} />
        <p className="eyebrow mb-1 mt-3">Uninstall</p>
        <CommandBlock cmd={`curl -fsSL ${origin}/agent/uninstall.sh | bash`} />
      </Panel>
    </div>
  );
}

function AgentInspector({ id }: { id: number | null }) {
  const { data, isLoading } = useAgent(id);
  const { remove, regenKey } = useAgentActions();
  const a = data;

  if (isLoading || !a) {
    return (
      <Panel title="Inspector">
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      </Panel>
    );
  }

  const report = a.latest_report?.report ?? {};
  const perf = report.performance ?? {};
  const cpu = perf.cpu ?? {};
  const mem = perf.memory ?? {};
  const proc = report.processes ?? {};
  const net = report.network ?? {};
  const sockets = net.sockets ?? {};
  const storage = (report.storage?.filesystems ?? [])[0] ?? {};

  return (
    <Panel
      title={a.hostname || a.ip || 'agent'}
      meta={a.status}
      actions={
        <div className="flex gap-1.5">
          <button
            className="btn px-2 py-1"
            onClick={() =>
              regenKey.mutate(a.id, {
                onSuccess: (r) =>
                  toast.info(`New key: ${(r as { agent_key: string }).agent_key.slice(0, 12)}…`),
              })
            }
          >
            Regen key
          </button>
          <button
            className="btn-danger px-2 py-1"
            onClick={() => {
              if (confirm(`Remove agent ${a.hostname || a.ip} from the console?`))
                remove.mutate(a.id, { onSuccess: () => toast.success('Agent removed') });
            }}
          >
            Delete
          </button>
        </div>
      }
    >
      <div className="grid gap-4 md:grid-cols-3">
        <Block title="Identity">
          <KV k="IP" v={a.ip} />
          <KV k="MAC" v={a.mac_address} />
          <KV k="OS" v={a.os} />
          <KV k="Kernel" v={a.os_info?.kernel} />
          <KV k="Agent" v={a.version} />
          <KV k="Last check-in" v={relativeTime(a.last_checkin)} />
        </Block>
        <Block title="Resources">
          <KV k="CPU" v={cpu.usage_percent != null ? `${cpu.usage_percent}%` : '—'} />
          <KV k="Memory" v={mem.used_percent != null ? `${mem.used_percent}%` : '—'} />
          <KV k="Root FS" v={storage.used_percent != null ? `${storage.used_percent}%` : '—'} />
          <KV k="Processes" v={proc.total} />
          <KV k="Threads" v={proc.threads} />
        </Block>
        <Block title="Inventory">
          <KV k="Packages" v={a.package_count} />
          <KV k="Open ports" v={a.port_count} />
          <KV k="CVE matches" v={a.vulns_matched} />
          <KV k="TCP established" v={sockets.tcp_established} />
          <KV k="Reported" v={formatDate(a.latest_report_at)} />
        </Block>
      </div>

      {(proc.top ?? []).length > 0 && (
        <div className="mt-4">
          <div className="eyebrow mb-2 border-b border-line-soft pb-1">Resource leaders</div>
          <div className="space-y-0.5 font-mono text-2xs text-text-soft">
            {(proc.top as any[]).slice(0, 10).map((p) => (
              <div key={p.pid} className="flex gap-2">
                <span className="w-14 text-muted">{p.pid}</span>
                <span className="flex-1 truncate">{p.command}</span>
                <span className="text-blue">{Number(p.cpu_percent).toFixed(1)}%</span>
                <span className="text-cyan">{Number(p.memory_percent).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow mb-2 border-b border-line-soft pb-1">{title}</div>
      {children}
    </div>
  );
}

function KV({ k, v }: { k: string; v?: unknown }) {
  return (
    <div className="flex gap-2 py-0.5 text-xs">
      <span className="w-28 shrink-0 font-mono text-2xs uppercase tracking-wide text-muted">{k}</span>
      <span className="text-text-soft">{v === null || v === undefined || v === '' ? '—' : String(v)}</span>
    </div>
  );
}

function CommandBlock({ cmd }: { cmd: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 overflow-x-auto rounded border border-line-soft bg-hover px-3 py-2 font-mono text-2xs text-text-soft">
        {cmd}
      </code>
      <button
        className="btn px-2 py-1"
        onClick={() => {
          navigator.clipboard?.writeText(cmd);
          toast.info('Copied');
        }}
      >
        Copy
      </button>
    </div>
  );
}
